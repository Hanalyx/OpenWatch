"""
OpenWatch Error Classification and Handling Service

Provides comprehensive error taxonomy and user-friendly guidance.
Enhanced with security sanitization to prevent information disclosure.
"""

import logging
from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field

from app.models.error_models import (
    ErrorCategory,
    ErrorSeverity,
    ScanErrorInternal,
    ScanErrorResponse,
    ValidationResultInternal,
    ValidationResultResponse,
)

from ..infrastructure.audit import get_security_audit_logger
from .sanitization import get_error_sanitization_service

logger = logging.getLogger(__name__)
sanitization_service = get_error_sanitization_service()
audit_logger = get_security_audit_logger()


class SecurityContext(BaseModel):
    """Security context for error classification."""

    hostname: str = ""
    username: str = ""
    auth_method: str = ""
    source_ip: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


def classify_authentication_error(context: SecurityContext) -> ScanErrorInternal:
    """
    Classify authentication errors based on context.

    Args:
        context: Security context with authentication details

    Returns:
        ScanErrorInternal with classified error details
    """
    return ScanErrorInternal(
        error_code="AUTH_GENERIC",
        category=ErrorCategory.AUTHENTICATION,
        severity=ErrorSeverity.ERROR,
        message="Authentication error occurred",
        technical_details={"context": context.dict()},
        user_guidance="Please check your authentication credentials and try again.",
    )


class ErrorClassificationService:
    """
    Main error classification service.

    This service classifies errors into user-friendly categories with
    actionable guidance. It delegates actual host validation to
    ReadinessValidatorService and focuses on error presentation.
    """

    def __init__(self) -> None:
        """Initialize the error classification service."""
        pass

    async def classify_error(self, error: Exception, context: Optional[Dict[str, Any]] = None) -> ScanErrorInternal:
        """
        Classify and enhance a generic error with actionable guidance.

        Args:
            error: The exception to classify
            context: Optional context about the operation that failed

        Returns:
            ScanErrorInternal with classified error details
        """
        context = context or {}
        error_str = str(error).lower()

        # Network errors
        if any(keyword in error_str for keyword in ["connection refused", "timeout", "unreachable"]):
            return ScanErrorInternal(
                error_code="NET_006",
                category=ErrorCategory.NETWORK,
                severity=ErrorSeverity.ERROR,
                message=f"Network connectivity issue: {str(error)}",
                technical_details={"original_error": str(error), "context": context},
                user_guidance="Check network connectivity and ensure target host is reachable",
                can_retry=True,
                retry_after=60,
            )

        # Authentication errors
        if any(
            keyword in error_str
            for keyword in [
                "permission denied",
                "authentication failed",
                "invalid credentials",
            ]
        ):
            return ScanErrorInternal(
                error_code="AUTH_005",
                category=ErrorCategory.AUTHENTICATION,
                severity=ErrorSeverity.ERROR,
                message=f"Authentication failed: {str(error)}",
                technical_details={"original_error": str(error), "context": context},
                user_guidance="Verify username and credentials are correct and have proper access",
            )

        # Resource errors
        if any(keyword in error_str for keyword in ["no space", "disk full", "out of memory"]):
            return ScanErrorInternal(
                error_code="RES_003",
                category=ErrorCategory.RESOURCE,
                severity=ErrorSeverity.ERROR,
                message=f"Resource constraint: {str(error)}",
                technical_details={"original_error": str(error), "context": context},
                user_guidance="Free up system resources (disk space, memory) and try again",
                can_retry=True,
                retry_after=300,
            )

        # Default to execution error
        return ScanErrorInternal(
            error_code="EXEC_001",
            category=ErrorCategory.EXECUTION,
            severity=ErrorSeverity.ERROR,
            message=f"Scan execution failed: {str(error)}",
            technical_details={"original_error": str(error), "context": context},
            user_guidance="An unexpected error occurred during scan execution. Check logs for more details.",
            can_retry=True,
        )

    async def validate_scan_prerequisites(
        self,
        hostname: str,
        port: int,
        username: str,
        auth_method: str,
        credential: str,
        host_id: Optional[str] = None,
        db=None,
        user_id: Optional[str] = None,
        source_ip: Optional[str] = None,
    ) -> ValidationResultInternal:
        """
        Pre-flight validation (DEPRECATED).

        This method previously delegated to ReadinessValidatorService for validation.
        The readiness validation feature has been deprecated as host information
        is now available on the Host Detail page.

        For Kensa compliance scanning, hosts are validated during scan execution.

        Args:
            hostname: Target hostname or IP
            port: SSH port
            username: SSH username
            auth_method: Authentication method (password, ssh_key)
            credential: Password or SSH private key
            host_id: Optional host UUID for database lookup
            db: Optional database session
            user_id: Optional user ID for audit logging
            source_ip: Optional source IP for audit logging

        Returns:
            ValidationResultInternal indicating validation can proceed
        """
        logger.info(f"Pre-flight validation called for {hostname}:{port} (deprecated - returning success)")

        # Return success - validation is now handled during scan execution
        return ValidationResultInternal(
            can_proceed=True,
            errors=[],
            warnings=[],
            pre_flight_duration=0.0,
            system_info={"hostname": hostname, "port": port},
            validation_checks={},
        )

    def _log_validation_audit(
        self,
        result: ValidationResultInternal,
        user_id: Optional[str],
        source_ip: Optional[str],
    ) -> None:
        """Log audit events for validation errors and warnings."""
        if result.errors or result.warnings:
            for error in result.errors + result.warnings:
                audit_logger.log_error_classification_event(
                    error_code=error.error_code,
                    technical_details=error.technical_details,
                    sanitized_response={
                        "error_code": error.error_code,
                        "category": error.category.value,
                        "severity": error.severity.value,
                        "can_retry": error.can_retry,
                    },
                    user_id=user_id,
                    source_ip=source_ip,
                    severity=error.severity,
                )

    def get_sanitized_validation_result(
        self,
        internal_result: ValidationResultInternal,
        user_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        user_role: Optional[str] = None,
        is_admin: bool = False,
    ) -> ValidationResultResponse:
        """
        Convert internal validation result to sanitized user response.

        This integrates with Security Fix 5 system information sanitization.

        Args:
            internal_result: Internal validation result with sensitive data
            user_id: User ID for audit logging
            source_ip: Source IP for audit logging
            user_role: User role for access control
            is_admin: Whether user has admin privileges

        Returns:
            ValidationResultResponse with sanitized data safe for API response
        """
        # Sanitize errors using existing error sanitization
        sanitized_errors = []
        for error in internal_result.errors:
            sanitized_error = sanitization_service.sanitize_error(error.dict(), user_id=user_id, source_ip=source_ip)
            # Convert SanitizedError to ScanErrorResponse
            scan_error_response = ScanErrorResponse(
                error_code=sanitized_error.error_code,
                category=sanitized_error.category,
                severity=sanitized_error.severity,
                message=sanitized_error.message,
                user_guidance=sanitized_error.user_guidance,
                can_retry=sanitized_error.can_retry,
                retry_after=sanitized_error.retry_after,
                documentation_url=sanitized_error.documentation_url,
                timestamp=sanitized_error.timestamp,
            )
            sanitized_errors.append(scan_error_response)

        # Sanitize warnings using existing error sanitization
        sanitized_warnings = []
        for warning in internal_result.warnings:
            sanitized_warning = sanitization_service.sanitize_error(
                warning.dict(), user_id=user_id, source_ip=source_ip
            )
            # Convert SanitizedError to ScanErrorResponse
            scan_warning_response = ScanErrorResponse(
                error_code=sanitized_warning.error_code,
                category=sanitized_warning.category,
                severity=sanitized_warning.severity,
                message=sanitized_warning.message,
                user_guidance=sanitized_warning.user_guidance,
                can_retry=sanitized_warning.can_retry,
                retry_after=sanitized_warning.retry_after,
                documentation_url=sanitized_warning.documentation_url,
                timestamp=sanitized_warning.timestamp,
            )
            sanitized_warnings.append(scan_warning_response)

        # Sanitize system information using Security Fix 5 integration
        sanitized_system_info = {}
        if internal_result.system_info:
            sanitized_system_info = sanitization_service.sanitize_system_info_context(
                internal_result.system_info,
                user_role=user_role,
                is_admin=is_admin,
                user_id=user_id,
                source_ip=source_ip,
            )

        return ValidationResultResponse(
            can_proceed=internal_result.can_proceed,
            errors=sanitized_errors,
            warnings=sanitized_warnings,
            pre_flight_duration=internal_result.pre_flight_duration,
            validation_checks=internal_result.validation_checks,
            system_info=sanitized_system_info,
        )


# Module-level singleton instance
_error_classification_service: Optional[ErrorClassificationService] = None


def get_error_classification_service() -> ErrorClassificationService:
    """
    Get or create the singleton ErrorClassificationService instance.

    This factory function ensures that only one instance of the service
    is created and reused throughout the application lifecycle.

    Returns:
        ErrorClassificationService: The singleton service instance.
    """
    global _error_classification_service
    if _error_classification_service is None:
        _error_classification_service = ErrorClassificationService()
    return _error_classification_service
