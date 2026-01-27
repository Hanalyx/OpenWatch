"""
Authorization Module - Resource-Based Access Control (ReBAC)

This module provides Zero Trust authorization services for OpenWatch,
implementing per-resource permission validation to prevent unauthorized
access to systems outside a user's permission scope.

Architecture Overview:
    The authorization module implements ReBAC (Resource-Based Access Control)
    with Zero Trust principles:

    1. Service Layer (service.py)
       - Core AuthorizationService class
       - Permission checking and validation
       - Bulk authorization support
       - Audit logging integration

    2. Models (../models/authorization_models.py)
       - Data structures for authorization decisions
       - Permission policies and cache
       - Audit events

    3. Middleware (../middleware/authorization_middleware.py)
       - Request interception for protected endpoints
       - Automatic permission validation

Design Philosophy:
    - Zero Trust: Every operation validated at resource level
    - Fail-Secure: Access denied on any error
    - Comprehensive Audit: All decisions logged
    - Least Privilege: Only explicitly permitted access

Security Features:
    - Per-host permission validation
    - Cross-host attack prevention
    - Bulk operation authorization
    - Risk scoring for anomaly detection
    - In-memory permission caching with TTL

Quick Start:
    from app.services.authorization import (
        AuthorizationService,
        get_authorization_service,
    )
    from app.models.authorization_models import (
        ActionType,
        ResourceIdentifier,
        ResourceType,
    )

    # Create service
    auth_service = get_authorization_service(db)

    # Check single permission
    resource = ResourceIdentifier(
        resource_type=ResourceType.HOST,
        resource_id="host-uuid-123"
    )
    result = await auth_service.check_permission(
        user_id="user-123",
        resource=resource,
        action=ActionType.SCAN
    )

    if result.decision == AuthorizationDecision.ALLOW:
        print("Access granted")
    else:
        print(f"Access denied: {result.reason}")

    # Check bulk permissions
    from app.models.authorization_models import BulkAuthorizationRequest

    bulk_request = BulkAuthorizationRequest(
        user_id="user-123",
        resources=[resource1, resource2, resource3],
        action=ActionType.SCAN,
        context=auth_context,
        fail_fast=True
    )
    bulk_result = await auth_service.check_bulk_permissions(bulk_request)

Module Structure:
    authorization/
    ├── __init__.py           # This file - public API
    └── service.py            # Core AuthorizationService

Related Components:
    - models/authorization_models.py: Data structures
    - middleware/authorization_middleware.py: Request interception
    - routes/authorization.py: REST API endpoints

Design by Emily (Security Engineer) & Implementation by Daniel (Backend Engineer)

Version: 1.0.0
"""

import logging

# Re-export commonly used models for convenience
# Note: Models stay in models/authorization_models.py per Option B pattern
from app.models.authorization_models import (  # noqa: F401
    ActionType,
    AuthorizationAuditEvent,
    AuthorizationConfiguration,
    AuthorizationContext,
    AuthorizationDecision,
    AuthorizationResult,
    BulkAuthorizationRequest,
    BulkAuthorizationResult,
    HostPermission,
    PermissionCache,
    PolicyConflictResolution,
    ResourceIdentifier,
    ResourceType,
)

# Import core service
from .service import AuthorizationService, get_authorization_service, sanitize_for_log

logger = logging.getLogger(__name__)

__all__ = [
    # Core service
    "AuthorizationService",
    "get_authorization_service",
    # Utility functions
    "sanitize_for_log",
    # Models (re-exported for convenience)
    "ActionType",
    "AuthorizationAuditEvent",
    "AuthorizationConfiguration",
    "AuthorizationContext",
    "AuthorizationDecision",
    "AuthorizationResult",
    "BulkAuthorizationRequest",
    "BulkAuthorizationResult",
    "HostPermission",
    "PermissionCache",
    "PolicyConflictResolution",
    "ResourceIdentifier",
    "ResourceType",
]

__version__ = "1.0.0"

logger.debug("Authorization module loaded")
