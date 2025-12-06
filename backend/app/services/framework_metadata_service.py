"""
Backward Compatibility Alias for Framework Metadata Service

DEPRECATED: This module is maintained for backward compatibility only.
Please update imports to use the new modular package:

    # NEW (Recommended)
    from backend.app.services.framework import FrameworkMetadataService

    # OLD (Deprecated - this file)
    from backend.app.services.framework_metadata_service import FrameworkMetadataService

This module will be removed in a future version.
Migration completed: 2025-12-05
"""

import warnings

# Issue deprecation warning on import
warnings.warn(
    "framework_metadata_service module is deprecated. " "Import from 'backend.app.services.framework' instead.",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export everything from the new location
from backend.app.services.framework.metadata import FrameworkMetadataService  # noqa: F401, E402

__all__ = [
    "FrameworkMetadataService",
]
