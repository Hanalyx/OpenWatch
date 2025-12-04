"""
Centralized Authentication Service (Backward Compatibility Re-exports)

DEPRECATED: This module is maintained for backward compatibility only.
Import from backend.app.services.auth instead.

Migration Guide:
    # OLD (deprecated)
    from backend.app.services.auth_service import (
        CentralizedAuthService,
        CredentialData,
        AuthMethod,
    )

    # NEW (recommended)
    from backend.app.services.auth import (
        CentralizedAuthService,
        CredentialData,
        AuthMethod,
    )

The auth/ module provides a cleaner, more organized structure:
- auth/models.py - Data models (CredentialData, AuthMethod, etc.)
- auth/exceptions.py - Custom exceptions
- auth/validation.py - Security policy validation
- auth/credential_service.py - Main credential service
"""

import warnings

# Re-export everything from the new auth module for backward compatibility
from .auth import (  # noqa: F401; Models; Exceptions; Validation; Service
    AuthMethod,
    AuthMethodMismatchError,
    CentralizedAuthService,
    CredentialData,
    CredentialDecryptionError,
    CredentialMetadata,
    CredentialNotFoundError,
    CredentialScope,
    CredentialSecurityValidator,
    CredentialValidationError,
    FIPSComplianceStatus,
    KeySecurityAssessment,
    SecurityPolicyConfig,
    SecurityPolicyLevel,
    get_auth_service,
    get_credential_validator,
    validate_credential_with_strict_policy,
)

# Issue deprecation warning on import
warnings.warn(
    "Importing from backend.app.services.auth_service is deprecated. "
    "Import from backend.app.services.auth instead.",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [
    # Models
    "CredentialData",
    "CredentialMetadata",
    "CredentialScope",
    "AuthMethod",
    # Exceptions
    "AuthMethodMismatchError",
    "CredentialNotFoundError",
    "CredentialValidationError",
    "CredentialDecryptionError",
    # Validation
    "SecurityPolicyLevel",
    "FIPSComplianceStatus",
    "KeySecurityAssessment",
    "SecurityPolicyConfig",
    "CredentialSecurityValidator",
    "get_credential_validator",
    "validate_credential_with_strict_policy",
    # Service
    "CentralizedAuthService",
    "get_auth_service",
]
