"""
OpenWatch Error Models
Provides both internal (with technical details) and sanitized (user-safe) error models
"""

from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field


class ErrorCategory(str, Enum):
    """Error category classification"""

    NETWORK = "network"
    AUTHENTICATION = "authentication"
    PRIVILEGE = "privilege"
    RESOURCE = "resource"
    DEPENDENCY = "dependency"
    CONTENT = "content"
    EXECUTION = "execution"
    CONFIGURATION = "configuration"
    SECURITY = "security"  # Added for rate limiting and security events


class ErrorSeverity(str, Enum):
    """Error severity levels"""

    CRITICAL = "critical"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class AutomatedFixResponse(BaseModel):
    """Sanitized automated fix response for users"""

    fix_id: str
    description: str
    requires_sudo: bool = False
    estimated_time: int = Field(default=30, description="Estimated time in seconds")
    is_safe: bool = True
    # Removed command and rollback_command fields for security


class ScanErrorInternal(BaseModel):
    """Internal scan error with full technical details (server-side only)"""

    error_code: str
    category: ErrorCategory
    severity: ErrorSeverity
    message: str
    technical_details: Dict[str, Any] = Field(default_factory=dict)
    user_guidance: str
    automated_fixes: List[Dict[str, Any]] = Field(default_factory=list)
    can_retry: bool = False
    retry_after: Optional[int] = Field(default=None, description="Retry after seconds")
    documentation_url: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ScanErrorResponse(BaseModel):
    """Sanitized scan error response for users (no sensitive data)"""

    error_code: str
    category: ErrorCategory
    severity: ErrorSeverity
    message: str
    user_guidance: str
    automated_fixes: List[AutomatedFixResponse] = Field(default_factory=list)
    can_retry: bool = False
    retry_after: Optional[int] = Field(default=None, description="Retry after seconds")
    documentation_url: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ValidationResultInternal(BaseModel):
    """Internal validation result with full technical details"""

    can_proceed: bool
    errors: List[ScanErrorInternal] = Field(default_factory=list)
    warnings: List[ScanErrorInternal] = Field(default_factory=list)
    pre_flight_duration: float = 0.0
    system_info: Dict[str, Any] = Field(default_factory=dict)  # Contains sensitive data
    validation_checks: Dict[str, bool] = Field(default_factory=dict)


class ValidationResultResponse(BaseModel):
    """Sanitized validation result response for users"""

    can_proceed: bool
    errors: List[ScanErrorResponse] = Field(default_factory=list)
    warnings: List[ScanErrorResponse] = Field(default_factory=list)
    pre_flight_duration: float = 0.0
    system_info: Dict[str, Any] = Field(default_factory=dict)  # Now sanitized via Security Fix 5
    validation_checks: Dict[str, bool] = Field(default_factory=dict)


class ErrorClassificationResponse(BaseModel):
    """Response from error classification endpoint"""

    error: ScanErrorResponse
    request_id: str
    rate_limit_info: Dict[str, Any] = Field(default_factory=dict)


class RateLimitResponse(BaseModel):
    """Response when rate limit is exceeded"""

    error_code: str = "RATE_LIMIT"
    message: str = "Request rate limit exceeded"
    retry_after: int  # Seconds to wait
    documentation_url: str = "https://docs.openwatch.dev/security/rate-limits"


class SecurityAuditLog(BaseModel):
    """Security audit log entry (server-side only)"""

    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: str
    error_code: str
    user_id: Optional[str] = None
    source_ip: Optional[str] = None
    session_id: Optional[str] = None
    technical_details: Dict[str, Any] = Field(default_factory=dict)
    sanitized_response: Dict[str, Any] = Field(default_factory=dict)
    severity: ErrorSeverity
    request_path: Optional[str] = None
    user_agent: Optional[str] = None


class ErrorStatistics(BaseModel):
    """Error statistics for monitoring (sanitized)"""

    total_errors: int = 0
    errors_by_category: Dict[str, int] = Field(default_factory=dict)
    errors_by_severity: Dict[str, int] = Field(default_factory=dict)
    top_error_codes: List[Dict[str, Any]] = Field(default_factory=list)
    time_window: str = "1h"
    # No IP addresses or user IDs exposed
