"""
Comprehensive API Error Handling Middleware for OpenWatch
Provides standardized error responses, logging, and monitoring
"""

import logging
import traceback
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class ErrorDetail(BaseModel):
    """Detailed error information"""

    field: Optional[str] = None
    message: str
    type: Optional[str] = None
    code: Optional[str] = None


class APIErrorResponse(BaseModel):
    """Standardized API error response"""

    success: bool = False
    error: str
    message: str
    details: List[ErrorDetail] = Field(default_factory=list)
    error_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    path: Optional[str] = None
    method: Optional[str] = None

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class ErrorType:
    """Standard error types for consistent handling"""

    VALIDATION_ERROR = "validation_error"
    AUTHENTICATION_ERROR = "authentication_error"
    AUTHORIZATION_ERROR = "authorization_error"
    NOT_FOUND_ERROR = "not_found_error"
    CONFLICT_ERROR = "conflict_error"
    RATE_LIMIT_ERROR = "rate_limit_error"
    SERVICE_ERROR = "service_error"
    DATABASE_ERROR = "database_error"
    CACHE_ERROR = "cache_error"
    EXTERNAL_API_ERROR = "external_api_error"
    INTERNAL_ERROR = "internal_error"


class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """Comprehensive error handling middleware with standardized responses"""

    def __init__(self, app, include_debug_info: bool = False):
        super().__init__(app)
        self.include_debug_info = include_debug_info

        # Error mappings for consistent handling
        self.error_mappings = {
            # HTTP status codes to error types
            400: ErrorType.VALIDATION_ERROR,
            401: ErrorType.AUTHENTICATION_ERROR,
            403: ErrorType.AUTHORIZATION_ERROR,
            404: ErrorType.NOT_FOUND_ERROR,
            409: ErrorType.CONFLICT_ERROR,
            429: ErrorType.RATE_LIMIT_ERROR,
            500: ErrorType.INTERNAL_ERROR,
            502: ErrorType.EXTERNAL_API_ERROR,
            503: ErrorType.SERVICE_ERROR,
            504: ErrorType.SERVICE_ERROR,
        }

        # User-friendly error messages
        self.user_messages = {
            ErrorType.VALIDATION_ERROR: "Invalid request data provided",
            ErrorType.AUTHENTICATION_ERROR: "Authentication required",
            ErrorType.AUTHORIZATION_ERROR: "Insufficient permissions",
            ErrorType.NOT_FOUND_ERROR: "Requested resource not found",
            ErrorType.CONFLICT_ERROR: "Request conflicts with current state",
            ErrorType.RATE_LIMIT_ERROR: "Too many requests - please try again later",
            ErrorType.SERVICE_ERROR: "Service temporarily unavailable",
            ErrorType.DATABASE_ERROR: "Database operation failed",
            ErrorType.CACHE_ERROR: "Cache operation failed",
            ErrorType.EXTERNAL_API_ERROR: "External service error",
            ErrorType.INTERNAL_ERROR: "Internal server error occurred",
        }

    async def dispatch(self, request: Request, call_next):
        """Handle errors and provide standardized responses"""
        try:
            response = await call_next(request)

            # Check for error status codes in successful responses
            if response.status_code >= 400:
                # Transform error responses to standard format if not already done
                return await self._handle_error_response(request, response)

            return response

        except HTTPException as http_exc:
            return await self._handle_http_exception(request, http_exc)

        except Exception as exc:
            return await self._handle_unexpected_exception(request, exc)

    async def _handle_http_exception(self, request: Request, exc: HTTPException) -> JSONResponse:
        """Handle FastAPI HTTP exceptions"""
        error_type = self.error_mappings.get(exc.status_code, ErrorType.INTERNAL_ERROR)

        # Parse exception details
        details = []
        if isinstance(exc.detail, str):
            details.append(ErrorDetail(message=exc.detail))
        elif isinstance(exc.detail, list):
            for item in exc.detail:
                if isinstance(item, dict):
                    details.append(
                        ErrorDetail(
                            field=item.get("loc", [])[-1] if item.get("loc") else None,
                            message=item.get("msg", "Validation error"),
                            type=item.get("type"),
                            code=item.get("code"),
                        )
                    )
                else:
                    details.append(ErrorDetail(message=str(item)))
        elif isinstance(exc.detail, dict):
            details.append(
                ErrorDetail(
                    message=exc.detail.get("message", "Error occurred"),
                    type=exc.detail.get("type"),
                    code=exc.detail.get("code"),
                )
            )

        error_response = APIErrorResponse(
            error=error_type,
            message=self.user_messages.get(error_type, str(exc.detail)),
            details=details,
            path=str(request.url.path),
            method=request.method,
        )

        # Log error with appropriate level
        if exc.status_code >= 500:
            logger.error(
                f"HTTP {exc.status_code} error: {exc.detail}",
                extra={
                    "error_id": error_response.error_id,
                    "path": request.url.path,
                    "method": request.method,
                },
            )
        else:
            logger.warning(
                f"HTTP {exc.status_code} error: {exc.detail}",
                extra={
                    "error_id": error_response.error_id,
                    "path": request.url.path,
                    "method": request.method,
                },
            )

        return JSONResponse(status_code=exc.status_code, content=error_response.dict())

    async def _handle_unexpected_exception(self, request: Request, exc: Exception) -> JSONResponse:
        """Handle unexpected exceptions"""
        error_id = str(uuid.uuid4())[:8]

        # Determine error type based on exception
        error_type = self._classify_exception(exc)
        status_code = self._get_status_code_for_exception(exc)

        # Create error details
        details = [ErrorDetail(message=str(exc), type=type(exc).__name__)]

        # Add debug information if enabled
        if self.include_debug_info:
            details.append(ErrorDetail(message=traceback.format_exc(), type="traceback"))

        error_response = APIErrorResponse(
            error=error_type,
            message=self.user_messages.get(error_type, "An unexpected error occurred"),
            details=details,
            error_id=error_id,
            path=str(request.url.path),
            method=request.method,
        )

        # Log the error with full context
        logger.error(
            f"Unexpected error ({error_id}): {str(exc)}",
            extra={
                "error_id": error_id,
                "error_type": error_type,
                "exception_type": type(exc).__name__,
                "path": request.url.path,
                "method": request.method,
                "traceback": traceback.format_exc(),
            },
        )

        return JSONResponse(status_code=status_code, content=error_response.dict())

    async def _handle_error_response(self, request: Request, response) -> JSONResponse:
        """Handle error responses that weren't caught as exceptions"""
        # This would be used to standardize error responses that come through normal flow
        return response

    def _classify_exception(self, exc: Exception) -> str:
        """Classify exception type for appropriate error categorization"""
        exc_name = type(exc).__name__.lower()

        # Database-related errors
        if any(db_type in exc_name for db_type in ["sql", "database", "connection", "operational"]):
            return ErrorType.DATABASE_ERROR

        # Cache-related errors
        if any(cache_type in exc_name for cache_type in ["redis", "cache", "memory"]):
            return ErrorType.CACHE_ERROR

        # Service-related errors
        if any(service_type in exc_name for service_type in ["timeout", "connection", "service"]):
            return ErrorType.SERVICE_ERROR

        # Validation errors
        if any(val_type in exc_name for val_type in ["validation", "value", "parse"]):
            return ErrorType.VALIDATION_ERROR

        # Permission errors
        if any(perm_type in exc_name for perm_type in ["permission", "forbidden", "unauthorized"]):
            return ErrorType.AUTHORIZATION_ERROR

        # Default to internal error
        return ErrorType.INTERNAL_ERROR

    def _get_status_code_for_exception(self, exc: Exception) -> int:
        """Get appropriate HTTP status code for exception type"""
        exc_name = type(exc).__name__.lower()

        # Map common exceptions to status codes
        if "notfound" in exc_name or "doesnotexist" in exc_name:
            return status.HTTP_404_NOT_FOUND

        if any(val_type in exc_name for val_type in ["validation", "value", "parse"]):
            return status.HTTP_400_BAD_REQUEST

        if any(perm_type in exc_name for perm_type in ["permission", "forbidden"]):
            return status.HTTP_403_FORBIDDEN

        if "unauthorized" in exc_name:
            return status.HTTP_401_UNAUTHORIZED

        if "timeout" in exc_name:
            return status.HTTP_504_GATEWAY_TIMEOUT

        if any(
            service_type in exc_name for service_type in ["connection", "service", "unavailable"]
        ):
            return status.HTTP_503_SERVICE_UNAVAILABLE

        # Default to internal server error
        return status.HTTP_500_INTERNAL_SERVER_ERROR


class APIValidationError(Exception):
    """Custom validation error for API operations"""

    def __init__(self, message: str, field: Optional[str] = None, code: Optional[str] = None):
        self.message = message
        self.field = field
        self.code = code
        super().__init__(message)


class APIServiceError(Exception):
    """Custom service error for API operations"""

    def __init__(
        self,
        message: str,
        service: Optional[str] = None,
        retry_after: Optional[int] = None,
    ):
        self.message = message
        self.service = service
        self.retry_after = retry_after
        super().__init__(message)


class APIAuthenticationError(Exception):
    """Custom authentication error"""

    def __init__(self, message: str = "Authentication required"):
        self.message = message
        super().__init__(message)


class APIAuthorizationError(Exception):
    """Custom authorization error"""

    def __init__(
        self,
        message: str = "Insufficient permissions",
        required_permission: Optional[str] = None,
    ):
        self.message = message
        self.required_permission = required_permission
        super().__init__(message)


class ErrorMonitor:
    """Monitor and track API errors for analysis"""

    def __init__(self):
        self.error_counts = {}
        self.error_patterns = {}
        self.last_reset = datetime.utcnow()

    def record_error(self, error_type: str, path: str, status_code: int):
        """Record error occurrence for monitoring"""
        key = f"{error_type}:{path}:{status_code}"

        if key not in self.error_counts:
            self.error_counts[key] = 0

        self.error_counts[key] += 1

        # Track patterns
        pattern_key = f"{error_type}:{status_code}"
        if pattern_key not in self.error_patterns:
            self.error_patterns[pattern_key] = []

        self.error_patterns[pattern_key].append(
            {
                "path": path,
                "timestamp": datetime.utcnow(),
                "count": self.error_counts[key],
            }
        )

    def get_error_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get error summary for monitoring"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)

        # Filter recent errors
        recent_errors = {}
        for pattern_key, errors in self.error_patterns.items():
            recent = [e for e in errors if e["timestamp"] > cutoff_time]
            if recent:
                recent_errors[pattern_key] = {
                    "count": len(recent),
                    "recent_paths": list(set(e["path"] for e in recent[-10:])),
                    "first_occurrence": min(e["timestamp"] for e in recent),
                    "last_occurrence": max(e["timestamp"] for e in recent),
                }

        return {
            "summary_period_hours": hours,
            "total_error_types": len(recent_errors),
            "errors_by_type": recent_errors,
            "generated_at": datetime.utcnow().isoformat(),
        }

    def reset_counters(self):
        """Reset error counters (typically called daily)"""
        self.error_counts.clear()
        self.error_patterns.clear()
        self.last_reset = datetime.utcnow()


# Global error monitor instance
_error_monitor = ErrorMonitor()


def get_error_monitor() -> ErrorMonitor:
    """Get the global error monitor instance"""
    return _error_monitor


# Utility functions for common error scenarios
def raise_validation_error(message: str, field: Optional[str] = None, code: Optional[str] = None):
    """Raise standardized validation error"""
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={
            "message": message,
            "field": field,
            "code": code,
            "type": ErrorType.VALIDATION_ERROR,
        },
    )


def raise_not_found_error(resource: str, identifier: Optional[str] = None):
    """Raise standardized not found error"""
    message = f"{resource} not found"
    if identifier:
        message += f": {identifier}"

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={
            "message": message,
            "resource": resource,
            "identifier": identifier,
            "type": ErrorType.NOT_FOUND_ERROR,
        },
    )


def raise_service_error(
    message: str, service: Optional[str] = None, retry_after: Optional[int] = None
):
    """Raise standardized service error"""
    headers = {}
    if retry_after:
        headers["Retry-After"] = str(retry_after)

    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={
            "message": message,
            "service": service,
            "retry_after": retry_after,
            "type": ErrorType.SERVICE_ERROR,
        },
        headers=headers,
    )


def raise_authorization_error(
    message: str = "Insufficient permissions", required_permission: Optional[str] = None
):
    """Raise standardized authorization error"""
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "message": message,
            "required_permission": required_permission,
            "type": ErrorType.AUTHORIZATION_ERROR,
        },
    )
