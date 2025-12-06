"""
Backward Compatibility Alias for Rule Association Service

DEPRECATED: This module is maintained for backward compatibility only.
Please update imports to use the new modular package:

    # NEW (Recommended)
    from backend.app.services.rules import (
        RuleAssociationService,
        RulePluginMapping,
        RuleMappingRecommendation,
        SemanticAnalysisResult,
        MappingConfidence,
        MappingSource,
        create_stig_mappings,
        create_cis_mappings,
    )

    # OLD (Deprecated - this file)
    from backend.app.services.rule_association_service import RuleAssociationService

This module will be removed in a future version.
Migration completed: 2025-12-05
"""

import warnings

# Issue deprecation warning on import
warnings.warn(
    "rule_association_service module is deprecated. " "Import from 'backend.app.services.rules' instead.",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export everything from the new location
from backend.app.services.rules.association import (  # noqa: F401, E402
    MappingConfidence,
    MappingSource,
    RuleAssociationService,
    RuleMappingRecommendation,
    RulePluginMapping,
    SemanticAnalysisResult,
    create_cis_mappings,
    create_stig_mappings,
)

__all__ = [
    "RuleAssociationService",
    "RulePluginMapping",
    "RuleMappingRecommendation",
    "SemanticAnalysisResult",
    "MappingConfidence",
    "MappingSource",
    "create_stig_mappings",
    "create_cis_mappings",
]
