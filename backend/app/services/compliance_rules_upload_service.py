"""
Backward Compatibility Alias for Compliance Rules Upload Service

DEPRECATED: This module is maintained for backward compatibility only.
Please update imports to use the new modular package:

    # NEW (Recommended)
    from backend.app.services.compliance_rules import (
        ComplianceRulesUploadService,
        get_upload_service,
    )

    # OLD (Deprecated - this file)
    from backend.app.services.compliance_rules_upload_service import (
        ComplianceRulesUploadService,
    )

This module will be removed in a future version.
Migration completed: 2025-12-05
"""

import warnings

# Issue deprecation warning on import
warnings.warn(
    "compliance_rules_upload_service module is deprecated. "
    "Import from 'backend.app.services.compliance_rules' instead.",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export everything from the new location
from backend.app.services.compliance_rules import ComplianceRulesUploadService, get_upload_service  # noqa: F401, E402

__all__ = [
    "ComplianceRulesUploadService",
    "get_upload_service",
]
