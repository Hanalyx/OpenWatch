"""
Versioning Submodule for Compliance Rules

Provides immutable versioning with content-addressed integrity for
FISMA/FedRAMP/HIPAA compliance requirements.

Components:
    - RuleVersioningService: Content hashing and change detection
    - HASH_EXCLUDE_FIELDS: Fields excluded from content hash
    - BREAKING_CHANGE_FIELDS: Fields that require re-scan when changed

Example:
    >>> from app.services.compliance_rules.versioning import (
    ...     RuleVersioningService,
    ...     HASH_EXCLUDE_FIELDS,
    ...     BREAKING_CHANGE_FIELDS,
    ... )
    >>>
    >>> # Calculate content hash
    >>> content_hash = RuleVersioningService.calculate_content_hash(rule_data)
    >>>
    >>> # Detect changes between versions
    >>> changes = RuleVersioningService.detect_changes(old_rule, new_rule)
    >>> if RuleVersioningService.has_breaking_changes(changes):
    ...     print("Re-scan required")
"""

from .service import BREAKING_CHANGE_FIELDS, HASH_EXCLUDE_FIELDS, RuleVersioningService  # noqa: F401

__all__ = [
    "RuleVersioningService",
    "HASH_EXCLUDE_FIELDS",
    "BREAKING_CHANGE_FIELDS",
]
