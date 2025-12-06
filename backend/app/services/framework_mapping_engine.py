"""
Backward Compatibility Alias for Framework Mapping Engine

DEPRECATED: This module is maintained for backward compatibility only.
Please update imports to use the new modular package:

    # NEW (Recommended)
    from backend.app.services.framework import (
        FrameworkMappingEngine,
        MappingConfidence,
        MappingType,
        ControlMapping,
        FrameworkRelationship,
        UnifiedImplementation,
    )

    # OLD (Deprecated - this file)
    from backend.app.services.framework_mapping_engine import FrameworkMappingEngine

This module will be removed in a future version.
Migration completed: 2025-12-05
"""

import warnings

# Issue deprecation warning on import
warnings.warn(
    "framework_mapping_engine module is deprecated. " "Import from 'backend.app.services.framework' instead.",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export everything from the new location
from backend.app.services.framework.engine import (  # noqa: F401, E402
    ControlMapping,
    FrameworkMappingEngine,
    FrameworkRelationship,
    MappingConfidence,
    MappingType,
    UnifiedImplementation,
)

__all__ = [
    "FrameworkMappingEngine",
    "MappingConfidence",
    "MappingType",
    "ControlMapping",
    "FrameworkRelationship",
    "UnifiedImplementation",
]
