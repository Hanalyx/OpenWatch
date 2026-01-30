"""
Validation Services Package for OpenWatch

Provides pre-scan validation, error classification, error sanitization,
and system information sanitization services.

Modules:
    unified: Pre-scan validation orchestration
    group: Host group validation
    errors: Error classification and user guidance
    sanitization: Error response sanitization
    system_sanitization: System info sanitization (anti-reconnaissance)

Usage:
    from app.services.validation import (
        ErrorClassificationService,
        get_error_classification_service,
        get_error_sanitization_service,
        GroupValidationService,
        ValidationError,
        UnifiedValidationService,
    )
"""

from app.models.error_models import AutomatedFixInternal

from .errors import (  # noqa: F401
    ErrorClassificationService,
    SecurityContext,
    classify_authentication_error,
    convert_readiness_result_to_validation,
    convert_readiness_to_error,
    get_error_classification_service,
)
from .group import GroupValidationService, OSFamily, ValidationError  # noqa: F401
from .sanitization import ErrorSanitizationService, SanitizationLevel, get_error_sanitization_service  # noqa: F401
from .system_sanitization import SystemInfoSanitizationService, get_system_info_sanitization_service  # noqa: F401
from .unified import UnifiedValidationService, ValidationRequest, get_unified_validation_service  # noqa: F401

# Backward-compatible alias: AutomatedFix was renamed to AutomatedFixInternal
# in error_models.py but some consumers still import AutomatedFix from this path
AutomatedFix = AutomatedFixInternal  # noqa: F401

__all__ = [
    # errors
    "ErrorClassificationService",
    "SecurityContext",
    "classify_authentication_error",
    "convert_readiness_to_error",
    "convert_readiness_result_to_validation",
    "get_error_classification_service",
    # group
    "GroupValidationService",
    "OSFamily",
    "ValidationError",
    # sanitization
    "ErrorSanitizationService",
    "SanitizationLevel",
    "get_error_sanitization_service",
    # system_sanitization
    "SystemInfoSanitizationService",
    "get_system_info_sanitization_service",
    # unified
    "UnifiedValidationService",
    "ValidationRequest",
    "get_unified_validation_service",
    # backward-compatible alias
    "AutomatedFix",
]
