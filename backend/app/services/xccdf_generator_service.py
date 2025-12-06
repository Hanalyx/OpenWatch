"""
Backward Compatibility Alias for XCCDF Generator Service

DEPRECATED: This module is maintained for backward compatibility only.
Please update imports to use the new modular package:

    # NEW (Recommended)
    from backend.app.services.xccdf import (
        XCCDFGeneratorService,
        get_xccdf_generator,
    )

    # OLD (Deprecated - this file)
    from backend.app.services.xccdf_generator_service import (
        XCCDFGeneratorService,
    )

This module will be removed in a future version.
Migration completed: 2025-12-05
"""

import warnings

# Issue deprecation warning on import
warnings.warn(
    "xccdf_generator_service module is deprecated. " "Import from 'backend.app.services.xccdf' instead.",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export everything from the new location
from backend.app.services.xccdf import XCCDFGeneratorService, get_xccdf_generator  # noqa: F401, E402

__all__ = [
    "XCCDFGeneratorService",
    "get_xccdf_generator",
]
