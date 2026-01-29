"""
OpenWatch Error Classification and Handling Service

Provides comprehensive error taxonomy and user-friendly guidance.
Enhanced with security sanitization to prevent information disclosure.

This module delegates host validation to ReadinessValidatorService (single source
of truth) and focuses on error classification, sanitization, and user guidance.

Architecture:
    - ReadinessValidatorService: Executes actual host validation checks
    - ErrorClassificationService: Classifies errors and sanitizes responses
    - This separation follows the Single Responsibility Principle
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.models.error_models import (
    AutomatedFixInternal,
    ErrorCategory,
    ErrorSeverity,
    ScanErrorInternal,
    ScanErrorResponse,
    ValidationResultInternal,
    ValidationResultResponse,
)
from app.models.readiness_models import HostReadiness, ReadinessCheckResult, ReadinessCheckSeverity, ReadinessCheckType

from ..security_audit_logger import get_security_audit_logger
from .sanitization import get_error_sanitization_service

logger = logging.getLogger(__name__)
sanitization_service = get_error_sanitization_service()
audit_logger = get_security_audit_logger()


# Error code mappings from ReadinessCheckType to error codes
CHECK_TYPE_TO_ERROR_CODE: Dict[str, str] = {
    ReadinessCheckType.OSCAP_INSTALLATION.value: "DEP_001",
    ReadinessCheckType.DISK_SPACE.value: "RES_001",
    ReadinessCheckType.MEMORY_AVAILABILITY.value: "RES_002",
    ReadinessCheckType.SUDO_ACCESS.value: "PRIV_001",
    ReadinessCheckType.SELINUX_STATUS.value: "PRIV_002",
    ReadinessCheckType.NETWORK_CONNECTIVITY.value: "NET_001",
    ReadinessCheckType.OPERATING_SYSTEM.value: "SYS_001",
    ReadinessCheckType.COMPONENT_DETECTION.value: "SYS_002",
    ReadinessCheckType.DEPENDENCIES.value: "DEP_002",
}

# Error category mappings from ReadinessCheckType
CHECK_TYPE_TO_CATEGORY: Dict[str, ErrorCategory] = {
    ReadinessCheckType.OSCAP_INSTALLATION.value: ErrorCategory.DEPENDENCY,
    ReadinessCheckType.DISK_SPACE.value: ErrorCategory.RESOURCE,
    ReadinessCheckType.MEMORY_AVAILABILITY.value: ErrorCategory.RESOURCE,
    ReadinessCheckType.SUDO_ACCESS.value: ErrorCategory.PRIVILEGE,
    ReadinessCheckType.SELINUX_STATUS.value: ErrorCategory.PRIVILEGE,
    ReadinessCheckType.NETWORK_CONNECTIVITY.value: ErrorCategory.NETWORK,
    ReadinessCheckType.OPERATING_SYSTEM.value: ErrorCategory.CONFIGURATION,
    ReadinessCheckType.COMPONENT_DETECTION.value: ErrorCategory.CONFIGURATION,
    ReadinessCheckType.DEPENDENCIES.value: ErrorCategory.DEPENDENCY,
}

# Automated fix suggestions for each check type
CHECK_TYPE_TO_FIXES: Dict[str, List[AutomatedFixInternal]] = {
    ReadinessCheckType.OSCAP_INSTALLATION.value: [
        AutomatedFixInternal(
            fix_id="install_openscap_rhel",
            description="[SECURITY] Use secure automated fix system to install OpenSCAP on RHEL/CentOS",
            command=None,
            requires_sudo=True,
            estimated_time=120,
            is_safe=False,
        ),
        AutomatedFixInternal(
            fix_id="install_openscap_ubuntu",
            description="[SECURITY] Use secure automated fix system to install OpenSCAP on Ubuntu/Debian",
            command=None,
            requires_sudo=True,
            estimated_time=120,
            is_safe=False,
        ),
    ],
    ReadinessCheckType.DISK_SPACE.value: [
        AutomatedFixInternal(
            fix_id="cleanup_tmp",
            description="[SECURITY] Use secure automated fix system to clean up files",
            command=None,
            requires_sudo=True,
            estimated_time=60,
            is_safe=False,
        ),
    ],
    ReadinessCheckType.SUDO_ACCESS.value: [
        AutomatedFixInternal(
            fix_id="add_sudoers_oscap",
            description="[SECURITY] Use secure automated fix system to configure sudo access",
            command=None,
            requires_sudo=True,
            estimated_time=30,
            is_safe=False,
        ),
    ],
    ReadinessCheckType.SELINUX_STATUS.value: [
        AutomatedFixInternal(
            fix_id="enable_selinux_openscap",
            description="[SECURITY] Use secure automated fix system to configure SELinux",
            command=None,
            requires_sudo=True,
            estimated_time=15,
            is_safe=False,
        ),
    ],
}

# Documentation URLs for each check type
CHECK_TYPE_TO_DOC_URL: Dict[str, str] = {
    ReadinessCheckType.OSCAP_INSTALLATION.value: "https://docs.openwatch.dev/troubleshooting/dependencies#openscap-installation",  # noqa: E501
    ReadinessCheckType.DISK_SPACE.value: "https://docs.openwatch.dev/troubleshooting/resources#disk-space",
    ReadinessCheckType.MEMORY_AVAILABILITY.value: "https://docs.openwatch.dev/troubleshooting/resources#memory",
    ReadinessCheckType.SUDO_ACCESS.value: "https://docs.openwatch.dev/troubleshooting/privileges#sudo-access",
    ReadinessCheckType.SELINUX_STATUS.value: "https://docs.openwatch.dev/troubleshooting/privileges#selinux",
    ReadinessCheckType.NETWORK_CONNECTIVITY.value: "https://docs.openwatch.dev/troubleshooting/network#connectivity",
    ReadinessCheckType.OPERATING_SYSTEM.value: "https://docs.openwatch.dev/troubleshooting/system#os-detection",
    ReadinessCheckType.COMPONENT_DETECTION.value: "https://docs.openwatch.dev/troubleshooting/system#components",
    ReadinessCheckType.DEPENDENCIES.value: "https://docs.openwatch.dev/troubleshooting/dependencies#general",
}


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


def convert_readiness_to_error(check_result: ReadinessCheckResult) -> ScanErrorInternal:
    """
    Convert a ReadinessCheckResult to ScanErrorInternal.

    This function maps the host_validator check results to the error classification
    format used by the API responses.

    Args:
        check_result: ReadinessCheckResult from ReadinessValidatorService

    Returns:
        ScanErrorInternal with error details and automated fix suggestions
    """
    # Get check type as string
    check_type = check_result.check_type if isinstance(check_result.check_type, str) else check_result.check_type.value

    # Map severity
    severity_map = {
        ReadinessCheckSeverity.ERROR.value: ErrorSeverity.ERROR,
        ReadinessCheckSeverity.WARNING.value: ErrorSeverity.WARNING,
        ReadinessCheckSeverity.INFO.value: ErrorSeverity.INFO,
        "error": ErrorSeverity.ERROR,
        "warning": ErrorSeverity.WARNING,
        "info": ErrorSeverity.INFO,
    }
    severity_value = check_result.severity if isinstance(check_result.severity, str) else check_result.severity.value
    severity = severity_map.get(severity_value, ErrorSeverity.ERROR)

    return ScanErrorInternal(
        error_code=CHECK_TYPE_TO_ERROR_CODE.get(check_type, "CHECK_001"),
        category=CHECK_TYPE_TO_CATEGORY.get(check_type, ErrorCategory.EXECUTION),
        severity=severity,
        message=check_result.message,
        technical_details=check_result.details,
        user_guidance=check_result.details.get("remediation", f"Check failed: {check_result.check_name}"),
        automated_fixes=CHECK_TYPE_TO_FIXES.get(check_type, []),
        can_retry=True,
        retry_after=60 if severity == ErrorSeverity.ERROR else None,
        documentation_url=CHECK_TYPE_TO_DOC_URL.get(check_type, ""),
    )


def convert_readiness_result_to_validation(
    readiness: HostReadiness,
    pre_flight_duration: float,
) -> ValidationResultInternal:
    """
    Convert HostReadiness to ValidationResultInternal.

    This function transforms the ReadinessValidatorService output format
    to the error classification format expected by the API.

    Args:
        readiness: HostReadiness result from ReadinessValidatorService
        pre_flight_duration: Duration of the validation in seconds

    Returns:
        ValidationResultInternal with errors, warnings, and system info
    """
    errors: List[ScanErrorInternal] = []
    warnings: List[ScanErrorInternal] = []

    for check in readiness.checks:
        if not check.passed:
            error = convert_readiness_to_error(check)
            if error.severity == ErrorSeverity.ERROR:
                errors.append(error)
            else:
                warnings.append(error)

    # Build validation_checks dict from readiness checks
    validation_checks = {}
    for check in readiness.checks:
        check_type = check.check_type if isinstance(check.check_type, str) else check.check_type.value
        validation_checks[check_type] = check.passed

    # Build system_info from readiness summary
    system_info = readiness.summary.copy() if readiness.summary else {}
    system_info["hostname"] = readiness.hostname
    system_info["ip_address"] = readiness.ip_address
    system_info["validation_status"] = (
        readiness.status.value if hasattr(readiness.status, "value") else readiness.status
    )

    # can_proceed should be True if there are no ERROR-severity issues
    # Warnings (like sudo_access) should not block the scan
    can_proceed = len(errors) == 0

    return ValidationResultInternal(
        can_proceed=can_proceed,
        errors=errors,
        warnings=warnings,
        pre_flight_duration=pre_flight_duration,
        system_info=system_info,
        validation_checks=validation_checks,
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
        Comprehensive pre-flight validation using ReadinessValidatorService.

        This method delegates to ReadinessValidatorService for actual validation
        and converts the results to the error classification format.

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
            ValidationResultInternal with validation results
        """
        from uuid import UUID

        from app.config import get_settings
        from app.database import get_db as get_db_session
        from app.encryption import EncryptionConfig, create_encryption_service
        from app.services.host_validator.readiness_validator import ReadinessValidatorService

        start_time = datetime.utcnow()

        logger.info(f"Starting pre-flight validation for ***REDACTED***@{hostname}:{port}")

        # Get database session if not provided
        if db is None:
            db = next(get_db_session())

        try:
            # If host_id provided, use ReadinessValidatorService directly
            if host_id:
                try:
                    host_uuid = UUID(host_id) if isinstance(host_id, str) else host_id

                    # Initialize encryption service for ReadinessValidatorService
                    settings = get_settings()
                    encryption_service = create_encryption_service(
                        master_key=settings.master_key, config=EncryptionConfig()
                    )

                    # Use ReadinessValidatorService for validation
                    validator = ReadinessValidatorService(
                        db=db,
                        encryption_service=encryption_service,
                    )

                    # Execute validation
                    readiness_result = await validator.validate_host(
                        host_id=host_uuid,
                        check_types=None,  # Run all checks
                        use_cache=False,  # Always run fresh for pre-flight
                        user_id=user_id,
                    )

                    duration = (datetime.utcnow() - start_time).total_seconds()

                    # Convert to ValidationResultInternal
                    result = convert_readiness_result_to_validation(
                        readiness=readiness_result,
                        pre_flight_duration=duration,
                    )

                    # Log audit events for errors and warnings
                    self._log_validation_audit(result, user_id, source_ip)

                    return result

                except ValueError as e:
                    logger.warning(f"Invalid host_id format: {e}")
                    # Fall through to return error

            # If no host_id or lookup failed, return error
            duration = (datetime.utcnow() - start_time).total_seconds()
            error = ScanErrorInternal(
                error_code="HOST_001",
                category=ErrorCategory.CONFIGURATION,
                severity=ErrorSeverity.ERROR,
                message="Host not found or invalid host_id",
                technical_details={"host_id": host_id, "hostname": hostname},
                user_guidance="Ensure the host exists in the system and host_id is valid",
                can_retry=False,
            )

            return ValidationResultInternal(
                can_proceed=False,
                errors=[error],
                warnings=[],
                pre_flight_duration=duration,
                system_info={},
                validation_checks={},
            )

        except Exception as e:
            logger.error(f"Pre-flight validation failed: {e}", exc_info=True)
            duration = (datetime.utcnow() - start_time).total_seconds()

            error = await self.classify_error(e, {"stage": "pre_flight_validation"})

            return ValidationResultInternal(
                can_proceed=False,
                errors=[error],
                warnings=[],
                pre_flight_duration=duration,
                system_info={},
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
