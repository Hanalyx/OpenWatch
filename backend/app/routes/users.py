"""
User Management API Routes
Handles user CRUD operations with role-based access control
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import List, Optional
from pydantic import BaseModel, EmailStr
from datetime import datetime
import logging

from ..database import get_db
from ..auth import get_current_user, pwd_context
from ..rbac import (
    require_permission,
    require_super_admin,
    require_admin,
    Permission,
    UserRole,
    RBACManager,
)

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
        result = db.execute(
            text(
                """
            SELECT name, display_name, description, permissions
            FROM roles 
            WHERE is_active = true
            ORDER BY 
                CASE name
                    WHEN 'super_admin' THEN 1
                    WHEN 'security_admin' THEN 2
                    WHEN 'security_analyst' THEN 3
                    WHEN 'compliance_officer' THEN 4
                    WHEN 'auditor' THEN 5
                    WHEN 'guest' THEN 6
                    ELSE 7
                END
        """
            )
        )

        roles = []
        for row in result:
            roles.append(
                RoleInfo(
                    name=row.name,
                    display_name=row.display_name,
                    description=row.description,
                    permissions=row.permissions if isinstance(row.permissions, list) else [],
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
        # Build query conditions
        conditions = ["1=1"]
        params = {}

        if search:
            conditions.append("(username ILIKE :search OR email ILIKE :search)")
            params["search"] = f"%{search}%"

        if role:
            conditions.append("role = :role")
            params["role"] = role.value

        if is_active is not None:
            conditions.append("is_active = :is_active")
            params["is_active"] = is_active

        where_clause = " AND ".join(conditions)

        # Get total count
        count_result = db.execute(
            text(
                f"""
            SELECT COUNT(*) as total FROM users WHERE {where_clause}
        """
            ),
            params,
        )
        total = count_result.fetchone().total

        # Get paginated results
        offset = (page - 1) * page_size
        params.update({"limit": page_size, "offset": offset})

        result = db.execute(
            text(
                f"""
            SELECT id, username, email, role, is_active, created_at, 
                   last_login, failed_login_attempts, locked_until
            FROM users 
            WHERE {where_clause}
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset
        """
            ),
            params,
        )

        users = []
        for row in result:
            users.append(
                UserResponse(
                    id=row.id,
                    username=row.username,
                    email=row.email,
                    role=UserRole(row.role),
                    is_active=row.is_active,
                    created_at=row.created_at.isoformat(),
                    last_login=row.last_login.isoformat() if row.last_login else None,
                    failed_login_attempts=row.failed_login_attempts,
                    locked_until=row.locked_until.isoformat() if row.locked_until else None,
                )
            )

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
        # Check if username or email already exists
        result = db.execute(
            text(
                """
            SELECT id FROM users WHERE username = :username OR email = :email
        """
            ),
            {"username": user_data.username, "email": user_data.email},
        )

        if result.fetchone():
            raise HTTPException(status_code=400, detail="Username or email already exists")

        # Hash password
        hashed_password = pwd_context.hash(user_data.password)

        # Create user
        insert_result = db.execute(
            text(
                """
            INSERT INTO users (username, email, hashed_password, role, is_active, created_at, failed_login_attempts, mfa_enabled)
            VALUES (:username, :email, :password, :role, :is_active, CURRENT_TIMESTAMP, 0, false)
            RETURNING id, created_at
        """
            ),
            {
                "username": user_data.username,
                "email": user_data.email,
                "password": hashed_password,
                "role": user_data.role.value,
                "is_active": user_data.is_active,
            },
        )

        row = insert_result.fetchone()
        db.commit()

        logger.info(f"User {user_data.username} created by {current_user.get('username')}")

        return UserResponse(
            id=row.id,
            username=user_data.username,
            email=user_data.email,
            role=user_data.role,
            is_active=user_data.is_active,
            created_at=row.created_at.isoformat(),
            last_login=None,
            failed_login_attempts=0,
            locked_until=None,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create user")


@router.get("/{user_id}", response_model=UserResponse)
@require_permission(Permission.USER_READ)
async def get_user(
    user_id: int, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    """Get user by ID"""
    try:
        result = db.execute(
            text(
                """
            SELECT id, username, email, role, is_active, created_at, 
                   last_login, failed_login_attempts, locked_until
            FROM users WHERE id = :user_id
        """
            ),
            {"user_id": user_id},
        )

        row = result.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")

        return UserResponse(
            id=row.id,
            username=row.username,
            email=row.email,
            role=UserRole(row.role),
            is_active=row.is_active,
            created_at=row.created_at.isoformat(),
            last_login=row.last_login.isoformat() if row.last_login else None,
            failed_login_attempts=row.failed_login_attempts,
            locked_until=row.locked_until.isoformat() if row.locked_until else None,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving user {user_id}: {e}")
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
        # Check if user exists
        result = db.execute(
            text("SELECT id, role FROM users WHERE id = :user_id"), {"user_id": user_id}
        )
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

        # Build update query with secure column mapping
        updates = []
        params = {"user_id": user_id}

        # Security Fix: Use explicit column mapping instead of f-string concatenation
        allowed_columns = {
            "username": "username = :username",
            "email": "email = :email",
            "role": "role = :role",
            "is_active": "is_active = :is_active",
            "password": "hashed_password = :password",
        }

        if user_data.username:
            updates.append(allowed_columns["username"])
            params["username"] = user_data.username

        if user_data.email:
            updates.append(allowed_columns["email"])
            params["email"] = user_data.email

        if user_data.role:
            updates.append(allowed_columns["role"])
            params["role"] = user_data.role.value

        if user_data.is_active is not None:
            updates.append(allowed_columns["is_active"])
            params["is_active"] = user_data.is_active

        if user_data.password:
            updates.append(allowed_columns["password"])
            params["password"] = pwd_context.hash(user_data.password)

        if not updates:
            raise HTTPException(status_code=400, detail="No fields to update")

        updates.append("updated_at = CURRENT_TIMESTAMP")
        # Security Fix: Use parameterized query construction
        update_query = "UPDATE users SET " + ", ".join(updates) + " WHERE id = :user_id"

        db.execute(text(update_query), params)
        db.commit()

        # Return updated user
        return await get_user(user_id, current_user, db)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating user {user_id}: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to update user")


@router.delete("/{user_id}")
@require_permission(Permission.USER_DELETE)
async def delete_user(
    user_id: int, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    """Delete user (super admin only)"""
    try:
        # Prevent self-deletion
        if current_user.get("id") == user_id:
            raise HTTPException(status_code=400, detail="Cannot delete your own account")

        # Check if user exists
        result = db.execute(
            text("SELECT username FROM users WHERE id = :user_id"), {"user_id": user_id}
        )
        user = result.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Soft delete (deactivate) instead of hard delete to preserve audit trails
        db.execute(
            text(
                """
            UPDATE users 
            SET is_active = false, updated_at = CURRENT_TIMESTAMP 
            WHERE id = :user_id
        """
            ),
            {"user_id": user_id},
        )

        db.commit()

        logger.info(f"User {user.username} deactivated by {current_user.get('username')}")
        return {"message": "User deactivated successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting user {user_id}: {e}")
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
            text("SELECT hashed_password FROM users WHERE id = :user_id"), {"user_id": user_id}
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
        db.execute(
            text(
                """
            UPDATE users 
            SET hashed_password = :password, updated_at = CURRENT_TIMESTAMP 
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
        logger.error(f"Error changing password for user {current_user.get('id')}: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to change password")


@router.get("/me/profile", response_model=UserResponse)
async def get_my_profile(
    current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
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
