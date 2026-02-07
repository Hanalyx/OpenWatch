"""
User Management API Routes.

Handles user CRUD operations with role-based access control.
Provides endpoints for user creation, update, deletion, and password management.
"""

import logging
from typing import Any, Dict, List, Optional, cast

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, EmailStr
from sqlalchemy import text
from sqlalchemy.orm import Session

from ...auth import get_current_user, pwd_context
from ...database import get_db
from ...rbac import Permission, RBACManager, UserRole, require_permission
from ...utils.logging_security import sanitize_id_for_log
from ...utils.mutation_builders import InsertBuilder, UpdateBuilder
from ...utils.query_builder import QueryBuilder
from ...utils.user_helpers import format_user_not_found_error, serialize_user_row

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/users", tags=["User Management"])


# Pydantic models
class UserBase(BaseModel):
    username: str
    email: EmailStr
    role: UserRole
    is_active: bool = True


class UserCreate(UserBase):
    password: str


class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    password: Optional[str] = None


class UserResponse(UserBase):
    id: int
    created_at: str
    last_login: Optional[str] = None
    failed_login_attempts: int
    locked_until: Optional[str] = None

    class Config:
        from_attributes = True


class UserListResponse(BaseModel):
    users: List[UserResponse]
    total: int
    page: int
    page_size: int


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


class RoleInfo(BaseModel):
    name: str
    display_name: str
    description: str
    permissions: List[str]


@router.get("/roles", response_model=List[RoleInfo])
async def list_roles(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[RoleInfo]:
    """
    List all available roles (admin only).

    Args:
        current_user: Authenticated user dictionary from token.
        db: Database session dependency.

    Returns:
        List of RoleInfo objects with role details and permissions.

    Raises:
        HTTPException: 403 if insufficient permissions, 500 on server error.
    """
    user_role = UserRole(current_user.get("role", "guest"))
    if not RBACManager.has_permission(user_role, Permission.USER_READ):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    try:
        # OW-REFACTOR-001B: Use QueryBuilder for parameterized SELECT with complex ORDER BY
        # Why: Eliminates manual SQL construction, consistent with Phase 1-3 pattern
        builder = (
            QueryBuilder("roles")
            .select("name", "display_name", "description", "permissions")
            .where("is_active = :is_active", True, "is_active")
            .order_by(
                """CASE name
                    WHEN 'super_admin' THEN 1
                    WHEN 'security_admin' THEN 2
                    WHEN 'security_analyst' THEN 3
                    WHEN 'compliance_officer' THEN 4
                    WHEN 'auditor' THEN 5
                    WHEN 'guest' THEN 6
                    ELSE 7
                END""",
                "ASC",
            )
        )
        query, params = builder.build()
        result = db.execute(text(query), params)

        roles = []
        for row in result:
            roles.append(
                RoleInfo(
                    name=row.name,
                    display_name=row.display_name,
                    description=row.description,
                    permissions=(row.permissions if isinstance(row.permissions, list) else []),
                )
            )

        return roles

    except Exception as e:
        logger.error(f"Error listing roles: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve roles")


@router.get("", response_model=UserListResponse)
async def list_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: Optional[str] = Query(None),
    role: Optional[UserRole] = Query(None),
    is_active: Optional[bool] = Query(None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> UserListResponse:
    """
    List users with pagination and filtering.

    Args:
        page: Page number (1-indexed).
        page_size: Number of users per page (max 100).
        search: Optional search term for username or email.
        role: Optional role filter.
        is_active: Optional active status filter.
        current_user: Authenticated user dictionary from token.
        db: Database session dependency.

    Returns:
        UserListResponse with users, total count, and pagination info.

    Raises:
        HTTPException: 403 if insufficient permissions, 500 on server error.
    """
    user_role = UserRole(current_user.get("role", "guest"))
    if not RBACManager.has_permission(user_role, Permission.USER_READ):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    try:
        # OW-REFACTOR-001B: Use QueryBuilder for count query with conditional filtering
        # Why: Eliminates manual query string construction, consistent with Phase 1-3 pattern
        count_builder = QueryBuilder("users")

        # Add search filter (username OR email)
        if search:
            count_builder.where("(username ILIKE :search OR email ILIKE :search)", f"%{search}%", "search")

        # Add role filter
        if role:
            count_builder.where("role = :role", role.value, "role")

        # Add is_active filter
        if is_active is not None:
            count_builder.where("is_active = :is_active", is_active, "is_active")

        count_query, count_params = count_builder.count_query()
        count_result = db.execute(text(count_query), count_params)
        count_row = count_result.fetchone()
        # Null safety for fetchone() which returns Optional[Row]
        total: int = count_row.total if count_row else 0

        # OW-REFACTOR-001B: Use QueryBuilder for main query with same filters and pagination
        # Why: Reduces SQL injection risk, improves maintainability
        builder = QueryBuilder("users").select(
            "id",
            "username",
            "email",
            "role",
            "is_active",
            "created_at",
            "last_login",
            "failed_login_attempts",
            "locked_until",
        )

        # Apply same filters as count query
        if search:
            builder.where("(username ILIKE :search OR email ILIKE :search)", f"%{search}%", "search")

        if role:
            builder.where("role = :role", role.value, "role")

        if is_active is not None:
            builder.where("is_active = :is_active", is_active, "is_active")

        # Add ordering and pagination
        builder.order_by("created_at", "DESC").paginate(page=page, per_page=page_size)

        query, params = builder.build()
        result = db.execute(text(query), params)

        # Phase 3: Use centralized serialization helper
        users = []
        for row in result:
            user_data = serialize_user_row(row)
            users.append(UserResponse(**user_data))

        return UserListResponse(users=users, total=total, page=page, page_size=page_size)

    except Exception as e:
        logger.error(f"Error listing users: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve users")


@router.post("", response_model=UserResponse)
@require_permission(Permission.USER_CREATE)
async def create_user(
    user_data: UserCreate,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> UserResponse:
    """
    Create a new user (super admin only).

    Args:
        user_data: User creation data including username, email, password, role.
        current_user: Authenticated user dictionary from token.
        db: Database session dependency.

    Returns:
        UserResponse with newly created user details.

    Raises:
        HTTPException: 400 if username/email exists, 500 on server error.
    """
    try:
        # OW-REFACTOR-001B: Use QueryBuilder for existence check
        # Why: Consistent with Phase 1-3 pattern, reduces SQL injection risk
        check_builder = QueryBuilder("users").select("id").where("(username = :username OR email = :email)")
        check_query, _ = check_builder.build()
        result = db.execute(
            text(check_query),
            {"username": user_data.username, "email": user_data.email},
        )

        if result.fetchone():
            raise HTTPException(status_code=400, detail="Username or email already exists")

        # Hash password
        hashed_password = pwd_context.hash(user_data.password)

        # Use InsertBuilder for type-safe, parameterized INSERT
        from datetime import datetime

        insert_builder = (
            InsertBuilder("users")
            .columns(
                "username",
                "email",
                "hashed_password",
                "role",
                "is_active",
                "created_at",
                "failed_login_attempts",
                "mfa_enabled",
            )
            .values(
                user_data.username,
                user_data.email,
                hashed_password,
                user_data.role.value,
                user_data.is_active,
                datetime.utcnow(),
                0,
                False,
            )
            .returning("id", "created_at")
        )
        insert_query, insert_params = insert_builder.build()
        insert_result = db.execute(text(insert_query), insert_params)

        row = insert_result.fetchone()
        db.commit()

        # Null safety for INSERT...RETURNING result
        if row is None:
            raise HTTPException(status_code=500, detail="Failed to create user - no data returned")

        logger.info(f"User {user_data.username} created by {current_user.get('username')}")

        # Phase 3: Create synthetic row object for serialization helper
        # Since we're combining request data with database result, we create a simple namespace
        from types import SimpleNamespace

        synthetic_row = SimpleNamespace(
            id=row.id,
            username=user_data.username,
            email=user_data.email,
            role=user_data.role.value,
            is_active=user_data.is_active,
            created_at=row.created_at,
            last_login=None,
            failed_login_attempts=0,
            locked_until=None,
        )
        serialized_data = serialize_user_row(synthetic_row)
        return UserResponse(**serialized_data)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create user")


@router.get("/{user_id}", response_model=UserResponse)
@require_permission(Permission.USER_READ)
async def get_user(
    user_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> UserResponse:
    """
    Get user by ID.

    Args:
        user_id: The numeric ID of the user to retrieve.
        current_user: Authenticated user dictionary from token.
        db: Database session dependency.

    Returns:
        UserResponse with user details.

    Raises:
        HTTPException: 404 if user not found, 500 on server error.
    """
    try:
        # OW-REFACTOR-001B: Use QueryBuilder for parameterized SELECT
        # Why: Consistent with Phase 1-3 pattern, eliminates manual SQL construction
        builder = (
            QueryBuilder("users")
            .select(
                "id",
                "username",
                "email",
                "role",
                "is_active",
                "created_at",
                "last_login",
                "failed_login_attempts",
                "locked_until",
            )
            .where("id = :user_id", user_id, "user_id")
        )
        query, params = builder.build()
        result = db.execute(text(query), params)

        row = result.fetchone()
        if not row:
            raise format_user_not_found_error(user_id)

        # Phase 3: Use centralized serialization helper
        user_data = serialize_user_row(row)
        return UserResponse(**user_data)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving user {sanitize_id_for_log(user_id)}: {type(e).__name__}")
        raise HTTPException(status_code=500, detail="Failed to retrieve user")


@router.put("/{user_id}", response_model=UserResponse)
@require_permission(Permission.USER_UPDATE)
async def update_user(
    user_id: int,
    user_data: UserUpdate,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> UserResponse:
    """
    Update user (admin only, or users can update themselves).

    Args:
        user_id: The numeric ID of the user to update.
        user_data: Fields to update (username, email, role, is_active, password).
        current_user: Authenticated user dictionary from token.
        db: Database session dependency.

    Returns:
        UserResponse with updated user details.

    Raises:
        HTTPException: 400/403/404 on validation errors, 500 on server error.
    """
    try:
        # OW-REFACTOR-001B: Use QueryBuilder for existence check
        # Why: Consistent with Phase 1-3 pattern
        check_builder = QueryBuilder("users").select("id", "role").where("id = :user_id", user_id, "user_id")
        query, params = check_builder.build()
        result = db.execute(text(query), params)
        existing_user = result.fetchone()
        if not existing_user:
            raise HTTPException(status_code=404, detail="User not found")

        # Non-super admins can only update themselves (except for role changes)
        current_user_role = UserRole(current_user.get("role", "guest"))
        is_self_update = current_user.get("id") == user_id

        if not RBACManager.has_permission(current_user_role, Permission.USER_MANAGE_ROLES):
            if not is_self_update:
                raise HTTPException(status_code=403, detail="Can only update your own profile")
            if user_data.role and user_data.role != UserRole(existing_user.role):
                raise HTTPException(status_code=403, detail="Cannot change your own role")

        # OW-REFACTOR-001B: Use UpdateBuilder with explicit column names
        # Why: Hardcoded column names prevent SQL injection (CodeQL requirement)
        # Note: users table does not have updated_at column, only created_at
        update_builder = UpdateBuilder("users")

        # Use set_if() for optional fields - only sets if value is not None
        update_builder.set_if("username", user_data.username)
        update_builder.set_if("email", user_data.email)

        # Role requires .value conversion from enum
        if user_data.role:
            update_builder.set("role", user_data.role.value)

        # is_active can be False, so check explicitly for not None
        if user_data.is_active is not None:
            update_builder.set("is_active", user_data.is_active)

        # Hash password before storing
        if user_data.password:
            update_builder.set("hashed_password", pwd_context.hash(user_data.password))

        # Check if any fields were set
        if not update_builder._set_clauses:
            raise HTTPException(status_code=400, detail="No fields to update")

        update_builder.where("id = :user_id", user_id, "user_id")
        update_query, update_params = update_builder.build()
        db.execute(text(update_query), update_params)
        db.commit()

        # Return updated user
        # Cast needed because @require_permission decorator returns Any
        result = await get_user(user_id, current_user, db)
        return cast(UserResponse, result)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating user {sanitize_id_for_log(user_id)}: {type(e).__name__}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to update user")


@router.delete("/{user_id}")
@require_permission(Permission.USER_DELETE)
async def delete_user(
    user_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, str]:
    """
    Delete user (super admin only).

    Performs a soft delete by setting is_active=False to preserve audit trails.

    Args:
        user_id: The numeric ID of the user to delete.
        current_user: Authenticated user dictionary from token.
        db: Database session dependency.

    Returns:
        Dictionary with success message.

    Raises:
        HTTPException: 400 if self-deletion, 404 if not found, 500 on server error.
    """
    try:
        # Prevent self-deletion
        if current_user.get("id") == user_id:
            raise HTTPException(status_code=400, detail="Cannot delete your own account")

        # OW-REFACTOR-001B: Use QueryBuilder for existence check
        # Why: Consistent with Phase 1-3 pattern
        check_builder = QueryBuilder("users").select("username").where("id = :user_id", user_id, "user_id")
        query, params = check_builder.build()
        result = db.execute(text(query), params)
        user = result.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Use UpdateBuilder for type-safe, parameterized UPDATE
        # Soft delete preserves audit trails
        # Note: users table does not have updated_at column, only created_at
        update_builder = UpdateBuilder("users").set("is_active", False).where("id = :user_id", user_id, "user_id")
        update_query, update_params = update_builder.build()
        db.execute(text(update_query), update_params)
        db.commit()

        logger.info(f"User {user.username} deactivated by {current_user.get('username')}")
        return {"message": "User deactivated successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting user {sanitize_id_for_log(user_id)}: {type(e).__name__}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to delete user")


@router.post("/change-password")
async def change_password(
    password_data: PasswordChangeRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, str]:
    """
    Change current user's password.

    Args:
        password_data: Current and new password.
        current_user: Authenticated user dictionary from token.
        db: Database session dependency.

    Returns:
        Dictionary with success message.

    Raises:
        HTTPException: 400 if current password wrong, 404 if not found, 500 on error.
    """
    try:
        user_id = current_user.get("id")

        # Get current hashed password
        pw_builder = QueryBuilder("users").select("hashed_password").where("id = :user_id", user_id, "user_id")
        pw_query, pw_params = pw_builder.build()
        result = db.execute(text(pw_query), pw_params)
        user = result.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Verify current password
        if not pwd_context.verify(password_data.current_password, user.hashed_password):
            raise HTTPException(status_code=400, detail="Current password is incorrect")

        # Hash new password
        new_hashed = pwd_context.hash(password_data.new_password)

        # Update password using UpdateBuilder
        # Note: users table does not have updated_at column, only created_at
        update_builder = (
            UpdateBuilder("users").set("hashed_password", new_hashed).where("id = :user_id", user_id, "user_id")
        )
        update_query, update_params = update_builder.build()
        db.execute(text(update_query), update_params)

        db.commit()

        logger.info(f"Password changed for user {current_user.get('username')}")
        return {"message": "Password changed successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Error changing password for user {sanitize_id_for_log(current_user.get('id'))}: {type(e).__name__}"
        )
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to change password")


@router.get("/me/profile", response_model=UserResponse)
async def get_my_profile(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> UserResponse:
    """
    Get current user's profile.

    Args:
        current_user: Authenticated user dictionary from token.
        db: Database session dependency.

    Returns:
        UserResponse with current user's details.
    """
    user_id = current_user.get("id")
    # User ID should always be present for authenticated users
    if user_id is None:
        raise HTTPException(status_code=401, detail="User ID not found in token")
    # Cast needed because @require_permission decorator returns Any
    result = await get_user(user_id, current_user, db)
    return cast(UserResponse, result)


@router.put("/me/profile", response_model=UserResponse)
async def update_my_profile(
    user_data: UserUpdate,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> UserResponse:
    """
    Update current user's profile.

    Note: Users cannot change their own role through this endpoint.

    Args:
        user_data: Fields to update (username, email, password only).
        current_user: Authenticated user dictionary from token.
        db: Database session dependency.

    Returns:
        UserResponse with updated user details.
    """
    # Remove role from update data - users cannot change their own role
    user_data.role = None
    user_id = current_user.get("id")
    # User ID should always be present for authenticated users
    if user_id is None:
        raise HTTPException(status_code=401, detail="User ID not found in token")
    # Cast needed because @require_permission decorator returns Any
    result = await update_user(user_id, user_data, current_user, db)
    return cast(UserResponse, result)
