"""
User Management API Routes
Handles user CRUD operations with role-based access control
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, EmailStr
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..auth import get_current_user, pwd_context
from ..database import get_db
from ..rbac import Permission, RBACManager, UserRole, require_permission
from ..utils.logging_security import sanitize_id_for_log
from ..utils.query_builder import QueryBuilder
from ..utils.user_helpers import format_user_not_found_error, serialize_user_row

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
async def list_roles(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """List all available roles (admin only)"""
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
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List users with pagination and filtering"""
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
        total = count_result.fetchone().total

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
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create a new user (super admin only)"""
    try:
        # OW-REFACTOR-001B: Use QueryBuilder for existence check
        # Why: Consistent with Phase 1-3 pattern, reduces SQL injection risk
        check_builder = QueryBuilder("users").select("id").where("username = :username OR email = :email", None, None)
        # Note: QueryBuilder doesn't support OR with different param values, use custom params
        query, _ = check_builder.build()
        result = db.execute(
            text(query.replace(":username OR email = :email", ":username OR email = :email")),
            {"username": user_data.username, "email": user_data.email},
        )

        if result.fetchone():
            raise HTTPException(status_code=400, detail="Username or email already exists")

        # Hash password
        hashed_password = pwd_context.hash(user_data.password)

        # NOTE: QueryBuilder is for SELECT queries only (OW-REFACTOR-001B)
        # For INSERT/UPDATE/DELETE, use raw SQL with parameterized queries
        query = text(
            """
            INSERT INTO users (username, email, hashed_password, role, is_active,
                             created_at, failed_login_attempts, mfa_enabled)
            VALUES (:username, :email, :hashed_password, :role, :is_active,
                    CURRENT_TIMESTAMP, :failed_login_attempts, :mfa_enabled)
            RETURNING id, created_at
        """
        )
        insert_result = db.execute(
            query,
            {
                "username": user_data.username,
                "email": user_data.email,
                "hashed_password": hashed_password,
                "role": user_data.role.value,
                "is_active": user_data.is_active,
                "failed_login_attempts": 0,
                "mfa_enabled": False,
            },
        )

        row = insert_result.fetchone()
        db.commit()

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
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get user by ID"""
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
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update user (admin only, or users can update themselves)"""
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

        # OW-REFACTOR-001B: Use QueryBuilder for conditional UPDATE
        # Why: Eliminates manual SQL construction, maintains security through parameterization
        update_data = {}

        if user_data.username:
            update_data["username"] = user_data.username

        if user_data.email:
            update_data["email"] = user_data.email

        if user_data.role:
            update_data["role"] = user_data.role.value

        if user_data.is_active is not None:
            update_data["is_active"] = user_data.is_active

        if user_data.password:
            update_data["hashed_password"] = pwd_context.hash(user_data.password)

        if not update_data:
            raise HTTPException(status_code=400, detail="No fields to update")

        # NOTE: QueryBuilder is for SELECT queries only (OW-REFACTOR-001B)
        # For INSERT/UPDATE/DELETE, use raw SQL with parameterized queries
        # Note: users table does not have updated_at column, only created_at
        # Build dynamic SET clause based on update_data
        set_clauses = ", ".join([f"{key} = :{key}" for key in update_data.keys()])
        update_query = text(
            f"""
            UPDATE users
            SET {set_clauses}
            WHERE id = :user_id
        """
        )
        update_params = {**update_data, "user_id": user_id}
        db.execute(update_query, update_params)
        db.commit()

        # Return updated user
        return await get_user(user_id, current_user, db)

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
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete user (super admin only)"""
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

        # NOTE: QueryBuilder is for SELECT queries only (OW-REFACTOR-001B)
        # For INSERT/UPDATE/DELETE, use raw SQL with parameterized queries
        # Soft delete preserves audit trails
        # Note: users table does not have updated_at column, only created_at
        update_query = text(
            """
            UPDATE users
            SET is_active = :is_active
            WHERE id = :user_id
        """
        )
        db.execute(update_query, {"is_active": False, "user_id": user_id})
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
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Change current user's password"""
    try:
        user_id = current_user.get("id")

        # Get current hashed password
        result = db.execute(
            text("SELECT hashed_password FROM users WHERE id = :user_id"),
            {"user_id": user_id},
        )
        user = result.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Verify current password
        if not pwd_context.verify(password_data.current_password, user.hashed_password):
            raise HTTPException(status_code=400, detail="Current password is incorrect")

        # Hash new password
        new_hashed = pwd_context.hash(password_data.new_password)

        # Update password
        # Note: users table does not have updated_at column, only created_at
        db.execute(
            text(
                """
            UPDATE users
            SET hashed_password = :password
            WHERE id = :user_id
        """
            ),
            {"password": new_hashed, "user_id": user_id},
        )

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
async def get_my_profile(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get current user's profile"""
    return await get_user(current_user.get("id"), current_user, db)


@router.put("/me/profile", response_model=UserResponse)
async def update_my_profile(
    user_data: UserUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update current user's profile"""
    # Remove role from update data - users cannot change their own role
    user_data.role = None
    return await update_user(current_user.get("id"), user_data, current_user, db)
