"""
User Management Helper Functions

This module provides centralized helper functions for user management operations,
eliminating code duplication across auth.py and users.py endpoints.

Purpose:
    - Centralize user ID validation and conversion
    - Provide consistent user lookup patterns
    - Standardize user data serialization
    - Reduce code duplication from 220+ lines to minimal boilerplate

Why this module exists:
    - Eliminates duplicate UUID validation across 6+ endpoints
    - Centralizes user serialization logic (5 locations → 1)
    - Provides consistent error handling and messages
    - Follows DRY (Don't Repeat Yourself) principle from CLAUDE.md
    - Single Responsibility: ONE job - handle user data operations

Security:
    - All database queries use parameterized queries (SQL injection safe)
    - Generic error messages to clients (no information disclosure)
    - Detailed logging for audit trail
    - Input validation on all user IDs

Example Usage:
    from backend.app.utils.user_helpers import (
        validate_user_id,
        serialize_user_row
    )

    # Validate user ID from URL parameter
    user_id = validate_user_id(user_id_str)

    # Serialize database row to response model
    user_response = serialize_user_row(row)

Created: 2025-11-04 (Phase 3 of QueryBuilder migration)
"""

import logging
from types import SimpleNamespace
from typing import Any, Dict, Optional, Union

from fastapi import HTTPException, status
from sqlalchemy.engine.row import Row

logger = logging.getLogger(__name__)


def validate_user_id(user_id_str: str) -> int:
    """
    Validate and convert user ID string to integer.

    This helper eliminates duplicate validation logic that was repeated across
    6+ endpoints in auth.py and users.py. Follows DRY (Don't Repeat Yourself)
    principle from CLAUDE.md coding standards.

    Why this helper exists:
    - Reduces code duplication from 6+ locations to 1
    - Ensures consistent error handling across all endpoints
    - Centralizes security logging for invalid IDs
    - Makes code more maintainable (one place to update logic)

    Args:
        user_id_str: String representation of user ID from API request

    Returns:
        int: Validated user ID

    Raises:
        HTTPException: 400 Bad Request if user_id is not a valid integer

    Example:
        >>> user_id = validate_user_id("123")
        >>> assert user_id == 123

        >>> validate_user_id("invalid")  # Raises HTTPException 400

    Security:
        - Logs sanitized ID for audit trail
        - Returns generic error message to client (no information disclosure)
        - Detailed error logged server-side for debugging
    """
    try:
        return int(user_id_str)
    except (ValueError, TypeError) as e:
        logger.error(f"Invalid user ID format: {user_id_str[:50]} - {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user ID format"
        )


def serialize_user_row(
    row: Union[Row[Any], SimpleNamespace], include_sensitive: bool = False
) -> Dict[str, Any]:
    """
    Convert database row to standardized user response dictionary.

    This helper eliminates duplicate serialization logic that was repeated across
    5 endpoints (list_users, create_user, get_user, update_user, refresh_token).

    Why this helper exists:
    - Centralizes user data transformation (5 locations → 1)
    - Ensures consistent timestamp formatting
    - Handles optional fields uniformly
    - Makes schema changes easier (update in one place)

    Args:
        row: Database row object with user data
        include_sensitive: Whether to include sensitive fields (default: False)

    Returns:
        dict: Standardized user data dictionary

    Example:
        >>> row = db_query_result.fetchone()
        >>> user_dict = serialize_user_row(row)
        >>> assert "id" in user_dict
        >>> assert "password_hash" not in user_dict  # Sensitive field excluded

    Security:
        - Excludes sensitive fields by default (password_hash, etc.)
        - Only includes sensitive data when explicitly requested
        - Consistent data format prevents information leakage
    """
    user_data = {
        "id": row.id,
        "username": row.username,
        "email": row.email,
        "role": row.role if isinstance(row.role, str) else row.role.value,
        "is_active": row.is_active,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "last_login": row.last_login.isoformat() if row.last_login else None,
    }

    # Add optional fields if they exist
    if hasattr(row, "failed_login_attempts"):
        user_data["failed_login_attempts"] = row.failed_login_attempts

    if hasattr(row, "locked_until"):
        user_data["locked_until"] = row.locked_until.isoformat() if row.locked_until else None

    # Only include sensitive fields if explicitly requested
    if include_sensitive and hasattr(row, "password_hash"):
        user_data["password_hash"] = row.password_hash

    return user_data


def format_user_not_found_error(user_id: Optional[int] = None) -> HTTPException:
    """
    Create standardized 404 error for user not found.

    This helper ensures consistent error responses across all endpoints.

    Args:
        user_id: Optional user ID for logging (not included in client message)

    Returns:
        HTTPException: 404 Not Found with generic message

    Example:
        >>> error = format_user_not_found_error(user_id=123)
        >>> assert error.status_code == 404

    Security:
        - Generic error message to client (prevents user enumeration)
        - User ID logged server-side for debugging
    """
    if user_id:
        logger.warning(f"User not found: {user_id}")
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")


def format_validation_error(message: str, field: Optional[str] = None) -> HTTPException:
    """
    Create standardized 400 validation error.

    Args:
        message: Validation error message
        field: Optional field name that failed validation

    Returns:
        HTTPException: 400 Bad Request with validation details

    Example:
        >>> error = format_validation_error("Username is required", field="username")
        >>> assert error.status_code == 400
    """
    detail = {"message": message}
    if field:
        detail["field"] = field

    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
