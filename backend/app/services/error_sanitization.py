"""
OpenWatch Error Response Sanitization Service
Removes sensitive information from error responses while maintaining actionable user guidance
"""

import re
import hashlib
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Forward reference for system info sanitization integration
# Will be imported later to avoid circular imports
_system_info_sanitization_service = None


class SanitizationLevel(str, Enum):
    """Levels of error information sanitization"""

    MINIMAL = "minimal"  # Remove only critical PII
    STANDARD = "standard"  # Remove all sensitive technical details
    STRICT = "strict"  # Remove all technical information


class AuditLogEntry(BaseModel):
    """Audit log entry for security events"""

    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: str
    error_code: str
    user_id: Optional[str] = None
    source_ip: Optional[str] = None
    technical_details: Dict[str, Any]
    sanitized_response: Dict[str, Any]
    severity: str


class SanitizedError(BaseModel):
    """User-safe error response model"""

    error_code: str
    category: str
    severity: str
    message: str
    user_guidance: str
    can_retry: bool = False
    retry_after: Optional[int] = None
    documentation_url: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    # No technical_details field - removed for security


class RateLimitState(BaseModel):
    """Rate limiting state for error endpoint access"""

    ip_address: str
    error_count: int = 0
    first_error_time: datetime = Field(default_factory=datetime.utcnow)
    last_error_time: datetime = Field(default_factory=datetime.utcnow)
    is_blocked: bool = False
    block_until: Optional[datetime] = None


class ErrorSanitizationService:
    """Service to sanitize error responses and prevent information disclosure"""

    # Rate limiting configuration
    MAX_ERRORS_PER_HOUR = 50
    MAX_ERRORS_PER_MINUTE = 10
    BLOCK_DURATION_MINUTES = 60

    # Sensitive information patterns to remove
    SENSITIVE_PATTERNS = [
        # Usernames and hostnames
        r'\b(username|user|login)\s*[:=]\s*["\']?([^"\':\s]+)["\']?',
        r'\b(hostname|host|server)\s*[:=]\s*["\']?([^"\':\s]+)["\']?',
        # SSH details
        r'publickey authentication failed for user\s+["\']?([^"\':\s]+)["\']?',
        r'SSH authentication failed:.*?for user\s+["\']?([^"\':\s]+)["\']?',
        r"ssh_exchange_identification:\s+.*",
        # System information
        r"(Linux|Windows|Darwin)\s+[\w\-\.]+\s+[\d\.]+",
        r"/[a-zA-Z0-9_\-/\.]+\.(sh|py|conf|cfg|ini|xml)",
        r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",
        # Configuration details
        r"port\s+\d+",
        r"timeout\s+\d+",
        r"connection\s+result\s+\d+",
        # OS release information
        r'VERSION_ID\s*=\s*["\'][^"\']+["\']',
        r'PRETTY_NAME\s*=\s*["\'][^"\']+["\']',
        r'NAME\s*=\s*["\'][^"\']+["\']',
        # Error details that leak information
        r"stderr:\s*.*",
        r"command:\s*.*",
        r"banner:\s*.*",
    ]

    # Generic error messages mapped by error code patterns
    GENERIC_MESSAGES = {
        # Network errors
        "NET_001": "Unable to resolve the target host address",
        "NET_002": "Cannot establish connection to target host",
        "NET_003": "Connection to target host timed out",
        "NET_004": "Unexpected service detected on target port",
        "NET_005": "Remote service not responding properly",
        "NET_006": "Network connectivity issue detected",
        # Authentication errors
        "AUTH_001": "Account is temporarily locked",
        "AUTH_002": "Authentication credentials are invalid",
        "AUTH_003": "SSH key format is invalid",
        "AUTH_004": "SSH key authentication failed",
        "AUTH_005": "Authentication failed",
        # Privilege errors
        "PRIV_001": "Insufficient privileges for scan operations",
        "PRIV_002": "Security policy blocking scan operations",
        # Resource errors
        "RES_001": "Insufficient disk space available",
        "RES_002": "Insufficient memory available",
        "RES_003": "System resource constraint detected",
        # Dependency errors
        "DEP_001": "Required scanner software not found",
        "DEP_002": "Scanner software version incompatible",
        "DEP_999": "System dependency validation failed",
        # Execution errors
        "EXEC_001": "Scan execution failed due to unexpected error",
    }

    def __init__(self):
        self.rate_limit_cache: Dict[str, RateLimitState] = {}
        self._cleanup_rate_limit_cache()

    def sanitize_error(
        self,
        error_data: Dict[str, Any],
        sanitization_level: SanitizationLevel = SanitizationLevel.STANDARD,
        user_id: Optional[str] = None,
        source_ip: Optional[str] = None,
    ) -> SanitizedError:
        """
        Sanitize error response by removing sensitive information

        Args:
            error_data: Original error data from ErrorClassificationService
            sanitization_level: Level of sanitization to apply
            user_id: User ID for audit logging
            source_ip: Source IP for rate limiting

        Returns:
            SanitizedError: Clean error response safe for users
        """

        # Check rate limiting first
        if source_ip and self._is_rate_limited(source_ip):
            logger.warning(f"Rate limited error request from IP: {source_ip}")
            return self._create_rate_limit_error()

        # Log full technical details for audit
        self._log_security_event(error_data, user_id, source_ip)

        # Extract error code and get generic message
        error_code = error_data.get("error_code", "UNKNOWN")
        generic_message = self.GENERIC_MESSAGES.get(
            error_code, "An error occurred during the operation"
        )

        # Create sanitized error response
        sanitized = SanitizedError(
            error_code=error_code,
            category=error_data.get("category", "execution"),
            severity=error_data.get("severity", "error"),
            message=generic_message,
            user_guidance=self._sanitize_guidance(error_data.get("user_guidance", "")),
            can_retry=error_data.get("can_retry", False),
            retry_after=error_data.get("retry_after"),
            documentation_url=error_data.get("documentation_url", ""),
        )

        # Update rate limiting
        if source_ip:
            self._update_rate_limit(source_ip)

        return sanitized

    def _sanitize_guidance(self, guidance: str) -> str:
        """Remove sensitive information from user guidance text"""
        sanitized = guidance

        for pattern in self.SENSITIVE_PATTERNS:
            sanitized = re.sub(pattern, "[REDACTED]", sanitized, flags=re.IGNORECASE)

        # Remove specific technical commands
        sanitized = re.sub(r"`[^`]+`", "[COMMAND_REDACTED]", sanitized)

        # Remove file paths
        sanitized = re.sub(r"/[/\w\-\.]+", "[PATH_REDACTED]", sanitized)

        # Keep guidance actionable but generic
        sanitized = self._make_guidance_generic(sanitized)

        return sanitized

    def _make_guidance_generic(self, guidance: str) -> str:
        """Convert specific guidance to generic actionable advice"""
        generic_replacements = {
            "Check if SSH service is running on port [REDACTED]": "Verify SSH service is running on the correct port",
            "Verify the hostname [REDACTED] is correct": "Verify the target hostname is correct",
            "Add public key to [PATH_REDACTED] on target host": "Ensure SSH public key is authorized on target host",
            "Configure passwordless sudo for [COMMAND_REDACTED]": "Configure appropriate system privileges for scanning",
            "Free up disk space in [PATH_REDACTED]": "Free up sufficient disk space on target system",
            "Check [COMMAND_REDACTED] service status": "Check required service status on target system",
        }

        result = guidance
        for specific, generic in generic_replacements.items():
            result = result.replace(specific, generic)

        return result

    def _is_rate_limited(self, source_ip: str) -> bool:
        """Check if source IP is rate limited"""
        if source_ip not in self.rate_limit_cache:
            return False

        state = self.rate_limit_cache[source_ip]

        # Check if currently blocked
        if state.is_blocked and state.block_until:
            if datetime.utcnow() < state.block_until:
                return True
            else:
                # Block expired, reset state
                state.is_blocked = False
                state.block_until = None
                state.error_count = 0

        return False

    def _update_rate_limit(self, source_ip: str):
        """Update rate limiting state for source IP"""
        now = datetime.utcnow()

        if source_ip not in self.rate_limit_cache:
            self.rate_limit_cache[source_ip] = RateLimitState(ip_address=source_ip)

        state = self.rate_limit_cache[source_ip]
        state.error_count += 1
        state.last_error_time = now

        # Check rate limits
        time_diff_minutes = (now - state.first_error_time).total_seconds() / 60
        time_diff_seconds = (now - state.first_error_time).total_seconds()

        # Reset counter if more than 1 hour has passed
        if time_diff_minutes > 60:
            state.error_count = 1
            state.first_error_time = now

        # Check per-minute limit
        elif time_diff_seconds < 60 and state.error_count > self.MAX_ERRORS_PER_MINUTE:
            self._block_ip(source_ip)

        # Check per-hour limit
        elif time_diff_minutes <= 60 and state.error_count > self.MAX_ERRORS_PER_HOUR:
            self._block_ip(source_ip)

    def _block_ip(self, source_ip: str):
        """Block IP address due to rate limit violation"""
        if source_ip in self.rate_limit_cache:
            state = self.rate_limit_cache[source_ip]
            state.is_blocked = True
            state.block_until = datetime.utcnow().replace(
                minute=datetime.utcnow().minute + self.BLOCK_DURATION_MINUTES
            )

            logger.warning(
                f"IP {source_ip} blocked for {self.BLOCK_DURATION_MINUTES} minutes due to rate limiting"
            )

    def _create_rate_limit_error(self) -> SanitizedError:
        """Create error response for rate-limited requests"""
        return SanitizedError(
            error_code="RATE_LIMIT",
            category="security",
            severity="error",
            message="Too many error requests detected",
            user_guidance="Please wait before retrying. Contact support if this continues.",
            can_retry=True,
            retry_after=self.BLOCK_DURATION_MINUTES * 60,  # Convert to seconds
            documentation_url="https://docs.openwatch.dev/security/rate-limits",
        )

    def _log_security_event(
        self,
        error_data: Dict[str, Any],
        user_id: Optional[str],
        source_ip: Optional[str],
    ):
        """Log full error details for security audit"""

        # Create audit log entry
        audit_entry = AuditLogEntry(
            event_type="error_classification",
            error_code=error_data.get("error_code", "UNKNOWN"),
            user_id=user_id,
            source_ip=source_ip,
            technical_details=error_data.get("technical_details", {}),
            sanitized_response={
                "error_code": error_data.get("error_code", "UNKNOWN"),
                "category": error_data.get("category", "execution"),
                "severity": error_data.get("severity", "error"),
                "message_pattern": self.GENERIC_MESSAGES.get(
                    error_data.get("error_code", "UNKNOWN"), "Generic error message"
                ),
            },
            severity=error_data.get("severity", "error"),
        )

        # Log to security audit log
        security_logger = logging.getLogger("security_audit")
        security_logger.info(
            f"Error Classification Event: {audit_entry.json()}",
            extra={
                "event_type": "error_classification",
                "error_code": audit_entry.error_code,
                "user_id": user_id,
                "source_ip": source_ip,
                "severity": audit_entry.severity,
            },
        )

        # Also log summary to main logger
        logger.info(f"Sanitized error response for {audit_entry.error_code} from IP {source_ip}")

    def _cleanup_rate_limit_cache(self):
        """Clean up expired rate limit entries"""
        now = datetime.utcnow()
        expired_ips = []

        for ip, state in self.rate_limit_cache.items():
            # Remove entries older than 2 hours
            time_diff_hours = (now - state.first_error_time).total_seconds() / 3600
            if time_diff_hours > 2:
                expired_ips.append(ip)

        for ip in expired_ips:
            del self.rate_limit_cache[ip]

        logger.debug(f"Cleaned up {len(expired_ips)} expired rate limit entries")

    def _sanitize_system_info_integration(
        self,
        system_info: Dict[str, Any],
        user_id: Optional[str],
        source_ip: Optional[str],
    ) -> Dict[str, Any]:
        """
        Integrate with system information sanitization service from Security Fix 5.
        This method bridges error sanitization with system info sanitization.
        """
        try:
            # Lazy import to avoid circular dependency
            global _system_info_sanitization_service
            if _system_info_sanitization_service is None:
                from .system_info_sanitization import (
                    get_system_info_sanitization_service,
                )

                _system_info_sanitization_service = get_system_info_sanitization_service()

            # Create sanitization context
            from ..models.system_models import (
                SystemInfoSanitizationContext,
                SystemInfoLevel,
            )

            context = SystemInfoSanitizationContext(
                user_id=user_id,
                source_ip=source_ip,
                access_level=SystemInfoLevel.BASIC,  # Default to basic for error contexts
                is_admin=False,  # Conservative default
                compliance_only=True,
            )

            # Apply integrated sanitization
            sanitized_info, metadata = (
                _system_info_sanitization_service.sanitize_system_information(system_info, context)
            )

            # Only keep safe metadata
            return {
                "validation_timestamp": sanitized_info.get("validation_timestamp"),
                "system_compatible": sanitized_info.get("system_compatible", True),
                "sanitization_applied": True,
                "access_level": "basic",
            }

        except Exception as e:
            logger.error(f"System info sanitization integration failed: {e}")
            # Fallback to basic safe info
            return {
                "validation_timestamp": system_info.get("validation_timestamp"),
                "sanitization_applied": True,
                "access_level": "basic",
                "error_fallback": True,
            }

    def sanitize_system_info_context(
        self,
        system_info: Dict[str, Any],
        user_role: Optional[str] = None,
        is_admin: bool = False,
        user_id: Optional[str] = None,
        source_ip: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Enhanced system information sanitization with role-based access.
        This is the main integration point with Security Fix 5.
        """
        try:
            # Lazy import to avoid circular dependency
            global _system_info_sanitization_service
            if _system_info_sanitization_service is None:
                from .system_info_sanitization import (
                    get_system_info_sanitization_service,
                )

                _system_info_sanitization_service = get_system_info_sanitization_service()

            # Create comprehensive sanitization context
            from ..models.system_models import (
                SystemInfoSanitizationContext,
                SystemInfoLevel,
            )

            # Determine access level based on user role
            access_level = SystemInfoLevel.BASIC
            if is_admin and user_role in ["SUPER_ADMIN", "SECURITY_ADMIN"]:
                access_level = SystemInfoLevel.ADMIN
            elif user_role in ["SYSTEM_ADMIN", "SCAN_OPERATOR"]:
                access_level = SystemInfoLevel.OPERATIONAL
            elif user_role in ["COMPLIANCE_OFFICER"]:
                access_level = SystemInfoLevel.COMPLIANCE

            context = SystemInfoSanitizationContext(
                user_id=user_id,
                user_role=user_role,
                source_ip=source_ip,
                access_level=access_level,
                is_admin=is_admin,
                compliance_only=(
                    access_level in [SystemInfoLevel.BASIC, SystemInfoLevel.COMPLIANCE]
                ),
            )

            # Apply sanitization
            sanitized_info, metadata = (
                _system_info_sanitization_service.sanitize_system_information(system_info, context)
            )

            # Add sanitization metadata
            sanitized_info["_metadata"] = {
                "sanitization_level": metadata.sanitization_level.value,
                "reconnaissance_filtered": metadata.reconnaissance_filtered,
                "admin_access_used": metadata.admin_access_used,
                "timestamp": metadata.collection_timestamp.isoformat(),
            }

            return sanitized_info

        except Exception as e:
            logger.error(f"Enhanced system info sanitization failed: {e}")
            # Fallback to basic sanitization
            return self._sanitize_system_info_integration(system_info, user_id, source_ip)

    def create_validation_result_sanitizer(
        self, validation_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Sanitize ValidationResult objects for safe user consumption"""

        sanitized_errors = []
        sanitized_warnings = []

        # Sanitize all errors
        for error in validation_result.get("errors", []):
            if isinstance(error, dict):
                sanitized_errors.append(self.sanitize_error(error).dict())
            else:
                # Handle ScanError objects
                sanitized_errors.append(self.sanitize_error(error.dict()).dict())

        # Sanitize all warnings
        for warning in validation_result.get("warnings", []):
            if isinstance(warning, dict):
                sanitized_warnings.append(self.sanitize_error(warning).dict())
            else:
                # Handle ScanError objects
                sanitized_warnings.append(self.sanitize_error(warning.dict()).dict())

        # Remove sensitive system info using integrated system sanitization
        sanitized_system_info = self._sanitize_system_info_integration(
            validation_result.get("system_info", {}), user_id, source_ip
        )

        return {
            "can_proceed": validation_result.get("can_proceed", False),
            "errors": sanitized_errors,
            "warnings": sanitized_warnings,
            "pre_flight_duration": validation_result.get("pre_flight_duration", 0.0),
            "system_info": sanitized_system_info,  # Sanitized system info
            "validation_checks": validation_result.get("validation_checks", {}),
        }

    def get_rate_limit_status(self, source_ip: str) -> Dict[str, Any]:
        """Get current rate limit status for an IP (for monitoring)"""
        if source_ip not in self.rate_limit_cache:
            return {"is_limited": False, "error_count": 0}

        state = self.rate_limit_cache[source_ip]
        return {
            "is_limited": self._is_rate_limited(source_ip),
            "error_count": state.error_count,
            "is_blocked": state.is_blocked,
            "block_until": state.block_until.isoformat() if state.block_until else None,
            "remaining_errors": max(0, self.MAX_ERRORS_PER_HOUR - state.error_count),
        }


# Global instance for dependency injection
_sanitization_service = None


def get_error_sanitization_service() -> ErrorSanitizationService:
    """Get or create the global error sanitization service"""
    global _sanitization_service
    if _sanitization_service is None:
        _sanitization_service = ErrorSanitizationService()
    return _sanitization_service
