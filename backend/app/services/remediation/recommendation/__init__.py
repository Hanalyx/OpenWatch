"""
Remediation Recommendation Submodule

Provides the RemediationRecommendationEngine for generating structured
remediation recommendations from compliance scan results.

This module is ORSA-compatible (OpenWatch Remediation System Adapter),
meaning its output can be consumed by external remediation systems.
"""

import logging

# Core engine and models
from .engine import (  # Enums; Models
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

logger = logging.getLogger(__name__)

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

logger.debug("Remediation recommendation submodule initialized")
