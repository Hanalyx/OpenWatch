"""
Backward Compatibility Alias for Rule Service

DEPRECATED: This module is maintained for backward compatibility only.
Please update imports to use the new modular package:

    # NEW (Recommended)
    from backend.app.services.rules import (
        RuleService,
        QueryPriority,
        ParameterResolution,
    )

    # OLD (Deprecated - this file)
    from backend.app.services.rule_service import RuleService

This module will be removed in a future version.
Migration completed: 2025-12-05
"""

import warnings

# Issue deprecation warning on import
warnings.warn(
    "rule_service module is deprecated. " "Import from 'backend.app.services.rules' instead.",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export everything from the new location
from backend.app.services.rules.service import ParameterResolution, QueryPriority, RuleService  # noqa: F401, E402

__all__ = [
    "RuleService",
    "QueryPriority",
    "ParameterResolution",
]
