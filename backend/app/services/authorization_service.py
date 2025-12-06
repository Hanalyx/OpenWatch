"""
Backward Compatibility Alias for Authorization Service

DEPRECATED: This module is maintained for backward compatibility only.
Please update imports to use the new modular package:

    # NEW (Recommended)
    from backend.app.services.authorization import (
        AuthorizationService,
        get_authorization_service,
    )

    # OLD (Deprecated - this file)
    from backend.app.services.authorization_service import (
        AuthorizationService,
        get_authorization_service,
    )

This module will be removed in a future version.
Migration completed: 2025-12-05
"""

import warnings

# Issue deprecation warning on import
warnings.warn(
    "authorization_service module is deprecated. " "Import from 'backend.app.services.authorization' instead.",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export everything from the new location
from backend.app.services.authorization import (  # noqa: F401, E402
    AuthorizationService,
    get_authorization_service,
    sanitize_for_log,
)

__all__ = [
    "AuthorizationService",
    "get_authorization_service",
    "sanitize_for_log",
]
