"""
Remediation Module - Unified API for compliance remediation operations

This module provides a comprehensive API for all remediation-related operations
in OpenWatch, including recommendation generation, workflow management,
scheduling, and system integration.

Architecture Overview:
    The remediation module follows a layered architecture:

    1. Recommendation Layer (remediation.recommendation)
       - Analyzes compliance gaps
       - Generates prioritized remediation recommendations
       - Provides ORSA-compatible output for external systems

    2. Orchestration Layer (remediation.orchestration) [future]
       - Coordinates remediation execution
       - Manages execution order and dependencies
       - Handles parallel vs sequential execution

    3. Execution Layer (remediation.remediators)
       - Executes remediation commands
       - Supports Bash, Ansible executors
       - Provides rollback capabilities

    4. Scheduling Layer (remediation.scheduler) [future]
       - Schedules remediation jobs
       - Manages maintenance windows
       - Handles recurring remediation

Design Philosophy:
    - ORSA Compatibility: Output format consumable by external remediation systems
    - Safety First: Dry-run by default, reversible operations preferred
    - Framework Agnostic: Works with any compliance framework (NIST, CIS, STIG)
    - Platform Aware: Platform-specific remediation implementations

Quick Start:
    from app.services.remediation import RemediationRecommendationEngine

    # Initialize engine
    engine = RemediationRecommendationEngine()

    # Generate recommendations from scan results
    recommendations = engine.generate_recommendations_from_results(
        results=scan_results,
        platform="rhel9",
        target_host_id="host-uuid",
    )

    # Get prioritized remediation plan
    plan = engine.prioritize_recommendations(recommendations)

Module Structure:
    remediation/
    ├── __init__.py              # This file - public API
    ├── recommendation/          # Recommendation engine
    │   ├── __init__.py
    │   └── engine.py            # RemediationRecommendationEngine
    ├── orchestration/           # Job orchestration [future]
    ├── scheduler/               # Job scheduling [future]
    └── remediators/             # Execution backends [to be moved]

Related Modules:
    - services.engine: SCAP scan execution
    - services.owca: Compliance intelligence
    - models.remediation_models: Data models
    - routes.remediation_api: REST API endpoints

Security Notes:
    - All remediation commands are logged for audit
    - Dry-run mode prevents accidental changes
    - Rollback scripts generated for reversible operations
    - Authorization checked before remediation execution

Performance Notes:
    - Recommendations cached for repeated access
    - Batch execution for efficiency
    - Parallel execution with dependency resolution
"""

import logging

# Core recommendation engine
from .recommendation import (  # Models
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

# Version of the remediation module API
__version__ = "1.0.0"


# =============================================================================
# Factory Functions
# =============================================================================


def get_recommendation_engine() -> RemediationRecommendationEngine:
    """
    Get a remediation recommendation engine instance.

    Factory function for creating RemediationRecommendationEngine instances.

    Returns:
        Configured RemediationRecommendationEngine instance.

    Example:
        >>> engine = get_recommendation_engine()
        >>> recommendations = engine.generate_recommendations_from_results(results)
    """
    return RemediationRecommendationEngine()


# Public API - everything that should be importable from this module
__all__ = [
    # Version
    "__version__",
    # Core engine
    "RemediationRecommendationEngine",
    # Models
    "RemediationCategory",
    "RemediationComplexity",
    "RemediationPriority",
    "RemediationRecommendation",
    "RemediationStep",
    "RemediationSystemCapability",
    "RemediationRule",
    "RemediationJob",
    # Factory functions
    "get_recommendation_engine",
]

# Module initialization logging
logger.debug("Remediation module initialized (v%s)", __version__)
