"""
Backward Compatibility Alias for Remediation Recommendation Engine

DEPRECATED: This module is maintained for backward compatibility only.
Please update imports to use the new modular package:

    # NEW (Recommended)
    from backend.app.services.remediation import (
        RemediationRecommendationEngine,
        RemediationPriority,
        RemediationCategory,
        RemediationComplexity,
        RemediationRecommendation,
        RemediationStep,
        RemediationSystemCapability,
        RemediationRule,
        RemediationJob,
    )

    # OLD (Deprecated - this file)
    from backend.app.services.remediation_recommendation_engine import (
        RemediationRecommendationEngine,
        ...
    )

This module will be removed in a future version.
Migration completed: 2025-12-05
"""

import warnings

# Issue deprecation warning on import
warnings.warn(
    "remediation_recommendation_engine module is deprecated. "
    "Import from 'backend.app.services.remediation' instead.",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export everything from the new location
from backend.app.services.remediation import (  # noqa: F401, E402
    RemediationCategory,
    RemediationComplexity,
    RemediationJob,
    RemediationPriority,
    RemediationRecommendation,
    RemediationRecommendationEngine,
    RemediationRule,
    RemediationStep,
    RemediationSystemCapability,
)

__all__ = [
    "RemediationRecommendationEngine",
    "RemediationCategory",
    "RemediationComplexity",
    "RemediationPriority",
    "RemediationRecommendation",
    "RemediationStep",
    "RemediationSystemCapability",
    "RemediationRule",
    "RemediationJob",
]
