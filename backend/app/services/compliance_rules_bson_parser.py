"""
Backward Compatibility Alias for BSON Parser Service

DEPRECATED: This module is maintained for backward compatibility only.
Please update imports to use the new modular package:

    # NEW (Recommended)
    from backend.app.services.compliance_rules import (
        BSONParserService,
        BSONParsingError,
        detect_file_format,
    )

    # Or from submodule directly
    from backend.app.services.compliance_rules.parsing import (
        BSONParserService,
        BSONParsingError,
        detect_file_format,
    )

    # OLD (Deprecated - this file)
    from backend.app.services.compliance_rules_bson_parser import (
        BSONParserService,
    )

This module will be removed in a future version.
Migration completed: 2025-12-05
"""

import warnings

# Issue deprecation warning on import
warnings.warn(
    "compliance_rules_bson_parser module is deprecated. "
    "Import from 'backend.app.services.compliance_rules.parsing' instead.",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export everything from the new location
from backend.app.services.compliance_rules.parsing import (  # noqa: F401, E402
    BSONParserService,
    BSONParsingError,
    detect_file_format,
)

__all__ = [
    "BSONParserService",
    "BSONParsingError",
    "detect_file_format",
]
