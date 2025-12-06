"""
Backward Compatibility Alias for Dependency Service

DEPRECATED: This module is maintained for backward compatibility only.
Please update imports to use the new modular package:

    # NEW (Recommended)
    from backend.app.services.compliance_rules import (
        RuleDependencyGraph,
        InheritanceResolver,
        INHERITABLE_FIELDS,
        NON_INHERITABLE_FIELDS,
    )

    # Or from submodule directly
    from backend.app.services.compliance_rules.dependency import (
        RuleDependencyGraph,
        InheritanceResolver,
        INHERITABLE_FIELDS,
        NON_INHERITABLE_FIELDS,
    )

    # OLD (Deprecated - this file)
    from backend.app.services.compliance_rules_dependency_service import (
        RuleDependencyGraph,
        InheritanceResolver,
    )

This module will be removed in a future version.
Migration completed: 2025-12-05
"""

import warnings

# Issue deprecation warning on import
warnings.warn(
    "compliance_rules_dependency_service module is deprecated. "
    "Import from 'backend.app.services.compliance_rules.dependency' instead.",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export everything from the new location
from backend.app.services.compliance_rules.dependency import (  # noqa: F401, E402
    INHERITABLE_FIELDS,
    NON_INHERITABLE_FIELDS,
    InheritanceResolver,
    RuleDependencyGraph,
)

__all__ = [
    "RuleDependencyGraph",
    "InheritanceResolver",
    "INHERITABLE_FIELDS",
    "NON_INHERITABLE_FIELDS",
]
