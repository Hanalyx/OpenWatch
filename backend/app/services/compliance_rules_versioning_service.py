"""
Backward Compatibility Alias for Versioning Service

DEPRECATED: This module is maintained for backward compatibility only.
Please update imports to use the new modular package:

    # NEW (Recommended)
    from backend.app.services.compliance_rules import (
        RuleVersioningService,
        HASH_EXCLUDE_FIELDS,
        BREAKING_CHANGE_FIELDS,
    )

    # Or from submodule directly
    from backend.app.services.compliance_rules.versioning import (
        RuleVersioningService,
        HASH_EXCLUDE_FIELDS,
        BREAKING_CHANGE_FIELDS,
    )

    # OLD (Deprecated - this file)
    from backend.app.services.compliance_rules_versioning_service import (
        RuleVersioningService,
    )

This module will be removed in a future version.
Migration completed: 2025-12-05
"""

import warnings

# Issue deprecation warning on import
warnings.warn(
    "compliance_rules_versioning_service module is deprecated. "
    "Import from 'backend.app.services.compliance_rules.versioning' instead.",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export everything from the new location
from backend.app.services.compliance_rules.versioning import (  # noqa: F401, E402
    BREAKING_CHANGE_FIELDS,
    HASH_EXCLUDE_FIELDS,
    RuleVersioningService,
)

__all__ = [
    "RuleVersioningService",
    "HASH_EXCLUDE_FIELDS",
    "BREAKING_CHANGE_FIELDS",
]
