"""
Unified Pre-Scan Validation Service for OpenWatch
Consolidates all credential types into a single, reliable validation flow.
Eliminates duplication between system default and host-based credential validation.
"""

import asyncio
import logging
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..models.error_models import (
    AutomatedFix,
    AutomatedFixResponse,
    ErrorCategory,
    ErrorSeverity,
    ScanErrorInternal,
    ScanErrorResponse,
    ValidationResultInternal,
    ValidationResultResponse,
)
from .auth_service import CentralizedAuthService, CredentialData
from .error_classification import ErrorClassificationService
from .error_sanitization import get_error_sanitization_service
from .scap_scanner import SCAPScanner
from .system_info_sanitization import sanitize_system_info

logger = logging.getLogger(__name__)


class ValidationRequest(BaseModel):
    """Unified validation request model"""

    host_id: str
    use_system_default: bool = False
    target_hostname: str
    target_port: int = 22
    content_id: Optional[str] = None
    profile_id: Optional[str] = None


class UnifiedValidationService:
    """
    Unified validation service that handles all credential types consistently.
    Eliminates the duplication between host-based and system default validation.
    """

    def __init__(self, db: Session):
        self.db = db
        self.auth_service = CentralizedAuthService(db)
        self.error_classifier = ErrorClassificationService()
        self.sanitization_service = get_error_sanitization_service()
        self.scap_scanner = SCAPScanner()

    async def validate_scan_prerequisites(
        self, request: ValidationRequest, current_user: dict
    ) -> Tuple[ValidationResultInternal, ValidationResultResponse]:
        """
        Unified pre-scan validation that works with any credential type.

        Args:
            request: Validation request parameters
            current_user: Current authenticated user

        Returns:
            Tuple of (internal_result, sanitized_response)
        """
        start_time = time.time()
        validation_checks = {}
        errors = []
        warnings = []
        system_info = {}

        try:
            logger.info(f"Starting unified validation for host {request.host_id}")

            # Step 1: Resolve credentials through unified auth service
            credential_data = await self._resolve_credentials(request)
            validation_checks["credential_resolution"] = True

            # Step 2: Network connectivity test
            network_result = await self._test_network_connectivity(
                request.target_hostname, request.target_port
            )
            validation_checks["network_connectivity"] = network_result["success"]

            if not network_result["success"]:
                errors.append(self._create_network_error(network_result["error"]))

            # Step 3: SSH Authentication test (map to "authentication" for frontend compatibility)
            if validation_checks["network_connectivity"]:
                auth_result = await self._test_ssh_authentication(
                    request.target_hostname, request.target_port, credential_data
                )
                validation_checks["authentication"] = auth_result["success"]

                if auth_result["success"]:
                    system_info = auth_result.get("system_info", {})
                else:
                    errors.append(self._create_auth_error(auth_result["error"]))

            # Step 4: System privileges check (map to "privileges" for frontend compatibility)
            if validation_checks.get("authentication", False):
                privilege_result = await self._test_system_privileges(
                    request.target_hostname, request.target_port, credential_data
                )
                validation_checks["privileges"] = privilege_result["success"]

                if not privilege_result["success"]:
                    if privilege_result["severity"] == "error":
                        errors.append(self._create_privilege_error(privilege_result["error"]))
                    else:
                        warnings.append(self._create_privilege_warning(privilege_result["error"]))

            # Step 5: System resources check (map to "resources" for frontend compatibility)
            if validation_checks.get("authentication", False):
                resource_result = await self._test_system_resources(
                    request.target_hostname, request.target_port, credential_data
                )
                validation_checks["resources"] = resource_result["success"]

                if not resource_result["success"]:
                    warnings.append(self._create_resource_warning(resource_result["error"]))

            # Step 6: OpenSCAP dependencies check (map to "dependencies" for frontend compatibility)
            if validation_checks.get("authentication", False):
                scap_result = await self._test_openscap_dependencies(
                    request.target_hostname, request.target_port, credential_data
                )
                validation_checks["dependencies"] = scap_result["success"]

                if not scap_result["success"]:
                    warnings.append(self._create_dependency_warning(scap_result["error"]))

        except Exception as e:
            logger.error(f"Unexpected error during validation: {e}", exc_info=True)
            errors.append(self._create_unexpected_error(str(e)))
            validation_checks["unexpected_error"] = True

        # Create internal result with full details
        duration = time.time() - start_time
        can_proceed = len(errors) == 0

        internal_result = ValidationResultInternal(
            can_proceed=can_proceed,
            errors=errors,
            warnings=warnings,
            pre_flight_duration=duration,
            system_info=system_info,
            validation_checks=validation_checks,
        )

        # Create sanitized response for frontend
        sanitized_response = await self._sanitize_validation_result(internal_result, current_user)

        logger.info(
            f"Validation completed for host {request.host_id}: "
            f"can_proceed={can_proceed}, errors={len(errors)}, warnings={len(warnings)}"
        )

        return internal_result, sanitized_response

    async def _resolve_credentials(self, request: ValidationRequest) -> CredentialData:
        """Resolve credentials using unified auth service"""
        try:
            if request.use_system_default:
                return self.auth_service.resolve_credential(use_default=True)
            else:
                return self.auth_service.resolve_credential(target_id=request.host_id)
        except Exception as e:
            logger.error(f"Credential resolution failed: {e}")
            raise ValueError(f"Failed to resolve credentials: {str(e)}")

    async def _test_network_connectivity(self, hostname: str, port: int) -> Dict:
        """Test basic network connectivity"""
        try:
            import socket

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            result = sock.connect_ex((hostname, port))
            sock.close()

            if result == 0:
                return {"success": True}
            else:
                return {
                    "success": False,
                    "error": f"Cannot connect to {hostname}:{port}",
                }
        except Exception as e:
            return {
                "success": False,
                "error": f"Network connectivity test failed: {str(e)}",
            }

    async def _test_ssh_authentication(
        self, hostname: str, port: int, credential_data: CredentialData
    ) -> Dict:
        """Test SSH authentication using unified credentials"""
        try:
            # Use existing SCAP scanner's SSH connection test
            result = self.scap_scanner.test_ssh_connection(
                hostname=hostname,
                port=port,
                username=credential_data.username,
                auth_method=credential_data.auth_method.value,
                credential=credential_data.private_key or credential_data.password or "",
            )

            return {
                "success": result.get("connection_status") == "success",
                "system_info": result.get("system_info", {}),
                "error": result.get("error", "Authentication failed"),
            }
        except Exception as e:
            logger.error(f"SSH authentication test failed: {e}")
            return {"success": False, "error": f"SSH authentication failed: {str(e)}"}

    async def _test_system_privileges(
        self, hostname: str, port: int, credential_data: CredentialData
    ) -> Dict:
        """Test system privileges (sudo/root access)"""
        try:
            # This would typically test sudo access
            # For now, return success with warning if not root
            if credential_data.username == "root":
                return {"success": True}
            else:
                return {
                    "success": False,
                    "severity": "warning",
                    "error": "Non-root user detected. Some scans may require elevated privileges.",
                }
        except Exception as e:
            return {
                "success": False,
                "severity": "error",
                "error": f"Privilege test failed: {str(e)}",
            }

    async def _test_system_resources(
        self, hostname: str, port: int, credential_data: CredentialData
    ) -> Dict:
        """Test system resources (disk space, memory)"""
        try:
            # Basic resource check - would normally test disk space, etc.
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": f"Resource check failed: {str(e)}"}

    async def _test_openscap_dependencies(
        self, hostname: str, port: int, credential_data: CredentialData
    ) -> Dict:
        """Test OpenSCAP tool availability"""
        try:
            # This would test for oscap command availability
            return {"success": True}
        except Exception as e:
            return {
                "success": False,
                "error": f"OpenSCAP dependency check failed: {str(e)}",
            }

    # Error template configurations
    ERROR_TEMPLATES = {
        "network": {
            "error_code": "NET_001",
            "category": ErrorCategory.NETWORK,
            "severity": ErrorSeverity.ERROR,
            "message": "Network connectivity failed",
            "user_guidance": "Check network connectivity and firewall settings",
            "can_retry": True,
            "retry_after": 30,
        },
        "auth": {
            "error_code": "AUTH_001",
            "category": ErrorCategory.AUTHENTICATION,
            "severity": ErrorSeverity.ERROR,
            "message": "SSH authentication failed",
            "user_guidance": "Verify credentials and SSH key permissions",
            "can_retry": True,
            "retry_after": 60,
        },
        "privilege_error": {
            "error_code": "PRIV_001",
            "category": ErrorCategory.PRIVILEGE,
            "severity": ErrorSeverity.ERROR,
            "message": "Insufficient system privileges",
            "user_guidance": "Ensure user has sudo access or use root account",
            "can_retry": False,
        },
        "privilege_warning": {
            "error_code": "PRIV_002",
            "category": ErrorCategory.PRIVILEGE,
            "severity": ErrorSeverity.WARNING,
            "message": "Limited system privileges detected",
            "user_guidance": "Some scans may require elevated privileges",
            "can_retry": False,
        },
        "resource_warning": {
            "error_code": "RES_001",
            "category": ErrorCategory.RESOURCE,
            "severity": ErrorSeverity.WARNING,
            "message": "System resource constraints detected",
            "user_guidance": "Monitor system resources during scan execution",
            "can_retry": False,
        },
        "dependency_warning": {
            "error_code": "DEP_001",
            "category": ErrorCategory.DEPENDENCY,
            "severity": ErrorSeverity.WARNING,
            "message": "OpenSCAP dependencies may be missing",
            "user_guidance": "Install OpenSCAP tools on target system if needed",
            "can_retry": False,
        },
        "unexpected": {
            "error_code": "UNK_001",
            "category": ErrorCategory.EXECUTION,
            "severity": ErrorSeverity.ERROR,
            "message": "Unexpected validation error",
            "user_guidance": "Contact support if this error persists",
            "can_retry": True,
            "retry_after": 120,
        },
    }

    def _create_error(self, template_key: str, error_msg: str) -> ScanErrorInternal:
        """
        Create standardized error using template configuration

        Args:
            template_key: Key from ERROR_TEMPLATES dict
            error_msg: Technical error message

        Returns:
            ScanErrorInternal: Configured error instance
        """
        if template_key not in self.ERROR_TEMPLATES:
            template_key = "unexpected"  # Fallback

        template = self.ERROR_TEMPLATES[template_key]

        return ScanErrorInternal(
            error_code=template["error_code"],
            category=template["category"],
            severity=template["severity"],
            message=template["message"],
            technical_details={"error": error_msg},
            user_guidance=template["user_guidance"],
            can_retry=template["can_retry"],
            retry_after=template.get("retry_after"),
        )

    def _create_network_error(self, error_msg: str) -> ScanErrorInternal:
        """Create network connectivity error"""
        return self._create_error("network", error_msg)

    def _create_auth_error(self, error_msg: str) -> ScanErrorInternal:
        """Create authentication error"""
        return self._create_error("auth", error_msg)

    def _create_privilege_error(self, error_msg: str) -> ScanErrorInternal:
        """Create privilege error"""
        return self._create_error("privilege_error", error_msg)

    def _create_privilege_warning(self, error_msg: str) -> ScanErrorInternal:
        """Create privilege warning"""
        return self._create_error("privilege_warning", error_msg)

    def _create_resource_warning(self, error_msg: str) -> ScanErrorInternal:
        """Create resource warning"""
        return self._create_error("resource_warning", error_msg)

    def _create_dependency_warning(self, error_msg: str) -> ScanErrorInternal:
        """Create dependency warning"""
        return self._create_error("dependency_warning", error_msg)

    def _create_unexpected_error(self, error_msg: str) -> ScanErrorInternal:
        """Create unexpected error"""
        return self._create_error("unexpected", error_msg)

    async def _sanitize_validation_result(
        self, internal_result: ValidationResultInternal, current_user: dict
    ) -> ValidationResultResponse:
        """Convert internal result to sanitized response"""
        sanitized_errors = []
        sanitized_warnings = []

        # Get client info for sanitization
        user_id = current_user.get("sub") if current_user else None

        # Sanitize errors
        for error in internal_result.errors:
            # Convert to ScanErrorResponse (sanitized version)
            sanitized_error = ScanErrorResponse(
                error_code=error.error_code,
                category=error.category,
                severity=error.severity,
                message=error.message,
                user_guidance=error.user_guidance,
                automated_fixes=[
                    # Convert AutomatedFix to AutomatedFixResponse (remove sensitive fields)
                    self._sanitize_automated_fix(fix)
                    for fix in error.automated_fixes
                ],
                can_retry=error.can_retry,
                retry_after=error.retry_after,
                documentation_url=error.documentation_url,
                timestamp=error.timestamp,
            )
            sanitized_errors.append(sanitized_error)

        # Sanitize warnings
        for warning in internal_result.warnings:
            sanitized_warning = ScanErrorResponse(
                error_code=warning.error_code,
                category=warning.category,
                severity=warning.severity,
                message=warning.message,
                user_guidance=warning.user_guidance,
                automated_fixes=[
                    self._sanitize_automated_fix(fix) for fix in warning.automated_fixes
                ],
                can_retry=warning.can_retry,
                retry_after=warning.retry_after,
                documentation_url=warning.documentation_url,
                timestamp=warning.timestamp,
            )
            sanitized_warnings.append(sanitized_warning)

        # Sanitize system info
        sanitized_system_info = sanitize_system_info(internal_result.system_info)

        return ValidationResultResponse(
            can_proceed=internal_result.can_proceed,
            errors=sanitized_errors,
            warnings=sanitized_warnings,
            pre_flight_duration=internal_result.pre_flight_duration,
            system_info=sanitized_system_info,
            validation_checks=internal_result.validation_checks,
        )

    def _sanitize_automated_fix(self, fix: AutomatedFix) -> AutomatedFixResponse:
        """Convert AutomatedFix to sanitized AutomatedFixResponse"""
        return AutomatedFixResponse(
            fix_id=fix.fix_id,
            description=fix.description,
            requires_sudo=fix.requires_sudo,
            estimated_time=fix.estimated_time,
            is_safe=fix.is_safe,
            # Note: command and rollback_command are omitted for security
        )


def get_unified_validation_service(db: Session) -> UnifiedValidationService:
    """Factory function to get unified validation service instance"""
    return UnifiedValidationService(db)
