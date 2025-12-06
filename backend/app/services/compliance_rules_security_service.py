"""
Backward Compatibility Alias for Security Service

DEPRECATED: This module is maintained for backward compatibility only.
Please update imports to use the new modular package:

    # NEW (Recommended)
    from backend.app.services.compliance_rules import (
        ComplianceRulesSecurityService,
        SecurityCheckResult,
    )

    # Or from submodule directly
    from backend.app.services.compliance_rules.validation import (
        ComplianceRulesSecurityService,
        SecurityCheckResult,
    )

    # OLD (Deprecated - this file)
    from backend.app.services.compliance_rules_security_service import (
        ComplianceRulesSecurityService,
    )

This module will be removed in a future version.
Migration completed: 2025-12-05
"""

import warnings

# Issue deprecation warning on import
warnings.warn(
    "compliance_rules_security_service module is deprecated. "
    "Import from 'backend.app.services.compliance_rules.validation' instead.",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export everything from the new location
from backend.app.services.compliance_rules.validation import (  # noqa: F401, E402
    ComplianceRulesSecurityService,
    SecurityCheckResult,
)

__all__ = [
    "ComplianceRulesSecurityService",
    "SecurityCheckResult",
]
