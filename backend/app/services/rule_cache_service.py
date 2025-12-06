"""
Backward Compatibility Alias for Rule Cache Service

DEPRECATED: This module is maintained for backward compatibility only.
Please update imports to use the new modular package:

    # NEW (Recommended)
    from backend.app.services.rules import (
        RuleCacheService,
        CacheStrategy,
        CachePriority,
        CacheMetrics,
        CacheEntry,
    )

    # OLD (Deprecated - this file)
    from backend.app.services.rule_cache_service import RuleCacheService

This module will be removed in a future version.
Migration completed: 2025-12-05
"""

import warnings

# Issue deprecation warning on import
warnings.warn(
    "rule_cache_service module is deprecated. " "Import from 'backend.app.services.rules' instead.",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export everything from the new location
from backend.app.services.rules.cache import (  # noqa: F401, E402
    CacheEntry,
    CacheMetrics,
    CachePriority,
    CacheStrategy,
    RuleCacheService,
)

__all__ = [
    "RuleCacheService",
    "CacheStrategy",
    "CachePriority",
    "CacheMetrics",
    "CacheEntry",
]
