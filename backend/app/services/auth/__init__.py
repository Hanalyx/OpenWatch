"""
Authentication and Credential Management Module

This module provides centralized credential management for OpenWatch, including:
- Credential storage with AES-256-GCM encryption
- Credential resolution (host-specific -> system default fallback)
- Security validation with FIPS compliance checking
- SSH key validation and metadata extraction

Usage:
    from app.services.auth import (
        # Models
        CredentialData,
        AuthMethod,
        CredentialScope,
        CredentialMetadata,
        # Service
        CentralizedAuthService,
        get_auth_service,
        # Exceptions
        AuthMethodMismatchError,
        CredentialNotFoundError,
        CredentialValidationError,
        # Validation
        SecurityPolicyLevel,
        validate_credential_with_strict_policy,
    )

    # Resolve credentials for a host
    auth_service = get_auth_service(db, encryption_service)
    credential = auth_service.resolve_credential(target_id=str(host.id))

    # credential.private_key is DECRYPTED - pass to SSH service
    ssh_manager.connect_with_credentials(
        hostname=host.ip_address,
        username=credential.username,
        credential=credential.private_key,  # Already decrypted!
        ...
    )

SSH Connection Pattern:
    See CLAUDE.md section "SSH Connection Best Practices" for the complete
    pattern that all services must follow when establishing SSH connections.

    The key principle: Always resolve credentials using this module's
    CentralizedAuthService, which returns CredentialData with DECRYPTED
    values. Never pass encrypted credentials to SSH services.
"""

# Service - Main credential management
from .credential_service import CentralizedAuthService, get_auth_service  # noqa: F401

# Exceptions - Error handling
from .exceptions import (  # noqa: F401
    AuthMethodMismatchError,
    CredentialDecryptionError,
    CredentialNotFoundError,
    CredentialValidationError,
)

# Models - Core data structures
from .models import AuthMethod, CredentialData, CredentialMetadata, CredentialScope  # noqa: F401

# Validation - Security policy enforcement
from .validation import (  # noqa: F401
    CredentialSecurityValidator,
    FIPSComplianceStatus,
    KeySecurityAssessment,
    SecurityPolicyConfig,
    SecurityPolicyLevel,
    get_credential_validator,
    validate_credential_with_strict_policy,
)

# Public API
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
