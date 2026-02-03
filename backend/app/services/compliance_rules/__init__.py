"""
Compliance Rules Module - Unified API for compliance rule operations

This module provides a comprehensive API for all compliance rule-related
operations in OpenWatch, including upload, validation, deduplication,
versioning, and dependency management.

Architecture Overview:
    The compliance_rules module follows a layered architecture:

    1. Upload Layer (upload.py)
       - Main orchestrator for rule uploads
       - Coordinates all other services
       - Handles archive processing

    2. Parsing Layer (parsing/)
       - BSON/JSON parsing
       - Schema validation
       - Rule normalization

    3. Validation Layer (validation/)
       - Security: File validation and scanning
       - Deduplication: Smart duplicate detection

    4. Dependency Layer (dependency/)
       - Rule dependency graph
       - Inheritance resolution
       - Circular dependency detection

    5. Versioning Layer (versioning/)
       - Immutable version management
       - Content hashing (SHA-256)
       - Breaking change detection

Design Philosophy:
    - Security First: All uploads validated before processing
    - Immutable Versioning: Rules are versioned, never overwritten
    - Smart Deduplication: Efficient handling of duplicate rules
    - Dependency Aware: Proper handling of rule inheritance

Quick Start:
    from app.services.compliance_rules import (
        ComplianceRulesUploadService,
        get_upload_service,
    )

    # Initialize upload service
    upload_service = get_upload_service()

    # Upload compliance rules archive
    result = await upload_service.upload_archive(
        archive_path=Path("/path/to/rules.tar.gz"),
        options={"deduplication_strategy": "smart_update"},
    )

Module Structure:
    compliance_rules/
    ├── __init__.py           # This file - public API
    ├── upload.py             # ComplianceRulesUploadService (orchestrator)
    ├── parsing/              # BSON/JSON parsing
    │   ├── __init__.py
    │   └── bson_parser.py    # BSONParserService
    ├── validation/           # Security and deduplication
    │   ├── __init__.py
    │   ├── security.py       # ComplianceRulesSecurityService
    │   └── deduplication.py  # SmartDeduplicationService
    ├── dependency/           # Dependency management
    │   ├── __init__.py
    │   └── graph.py          # RuleDependencyGraph, InheritanceResolver
    └── versioning/           # Version management
        ├── __init__.py
        └── service.py        # RuleVersioningService

Related Modules:
    - services.content: SCAP content processing
    - repositories.compliance_repository: MongoDB access layer
    - models.mongo_models: ComplianceRule model

Security Notes:
    - All archives validated before extraction
    - Path traversal prevention on all file operations
    - File size limits enforced
    - Malicious content scanning

Performance Notes:
    - Batch processing for large uploads
    - Progress tracking for long operations
    - Efficient duplicate detection via hashing
"""

import logging

# =============================================================================
# Dependency Submodule
# =============================================================================
from .dependency import (  # noqa: F401
    INHERITABLE_FIELDS,
    NON_INHERITABLE_FIELDS,
    InheritanceResolver,
    RuleDependencyGraph,
)

# =============================================================================
# Parsing Submodule
# =============================================================================
from .parsing import BSONParserService, BSONParsingError, detect_file_format  # noqa: F401

# =============================================================================
# Core Upload Service
# =============================================================================
from .upload import ComplianceRulesUploadService  # noqa: F401

# =============================================================================
# Validation Submodule (Security + Deduplication)
# =============================================================================
from .validation import (  # noqa: F401; Security validation; Deduplication
    ComplianceRulesSecurityService,
    DeduplicationStrategy,
    SecurityCheckResult,
    SmartDeduplicationService,
)

# =============================================================================
# Versioning Submodule
# =============================================================================
from .versioning import BREAKING_CHANGE_FIELDS, HASH_EXCLUDE_FIELDS, RuleVersioningService  # noqa: F401

logger = logging.getLogger(__name__)

# Version of the compliance rules module API
__version__ = "2.0.0"


# =============================================================================
# Factory Functions
# =============================================================================


def get_upload_service() -> ComplianceRulesUploadService:
    """
    Get a compliance rules upload service instance.

    Factory function for creating ComplianceRulesUploadService instances.

    Returns:
        Configured ComplianceRulesUploadService instance.

    Example:
        >>> upload_service = get_upload_service()
        >>> result = await upload_service.upload_archive(archive_path)
    """
    return ComplianceRulesUploadService()


def get_parser_service() -> BSONParserService:
    """
    Get a BSON parser service instance.

    Factory function for creating BSONParserService instances.

    Returns:
        Configured BSONParserService instance.

    Example:
        >>> parser = get_parser_service()
        >>> rule_data = await parser.parse_bson_file(file_path)
    """
    return BSONParserService()


def get_security_service() -> ComplianceRulesSecurityService:
    """
    Get a compliance rules security service instance.

    Factory function for creating ComplianceRulesSecurityService instances.

    Returns:
        Configured ComplianceRulesSecurityService instance.

    Example:
        >>> security = get_security_service()
        >>> result = await security.validate_archive(archive_path)
    """
    return ComplianceRulesSecurityService()


def get_deduplication_service() -> SmartDeduplicationService:
    """
    Get a smart deduplication service instance.

    Factory function for creating SmartDeduplicationService instances.

    Returns:
        Configured SmartDeduplicationService instance.

    Example:
        >>> dedup = get_deduplication_service()
        >>> result = await dedup.check_duplicates(rules)
    """
    return SmartDeduplicationService()


def get_dependency_graph() -> RuleDependencyGraph:
    """
    Get a rule dependency graph instance.

    Factory function for creating RuleDependencyGraph instances.

    Returns:
        Configured RuleDependencyGraph instance.

    Example:
        >>> graph = get_dependency_graph()
        >>> graph.add_rule(rule)
        >>> deps = graph.get_dependencies(rule_id)
    """
    return RuleDependencyGraph()


def get_inheritance_resolver() -> InheritanceResolver:
    """
    Get an inheritance resolver instance.

    Factory function for creating InheritanceResolver instances.

    Returns:
        Configured InheritanceResolver instance.

    Example:
        >>> resolver = get_inheritance_resolver()
        >>> resolved = await resolver.resolve_inheritance(rule)
    """
    return InheritanceResolver()


# =============================================================================
# Public API
# =============================================================================

# Everything that should be importable from this module
__all__ = [
    # Version
    "__version__",
    # Core service
    "ComplianceRulesUploadService",
    # Parsing
    "BSONParserService",
    "BSONParsingError",
    "detect_file_format",
    # Security validation
    "ComplianceRulesSecurityService",
    "SecurityCheckResult",
    # Deduplication
    "SmartDeduplicationService",
    "DeduplicationStrategy",
    # Dependency management
    "RuleDependencyGraph",
    "InheritanceResolver",
    "INHERITABLE_FIELDS",
    "NON_INHERITABLE_FIELDS",
    # Versioning
    "RuleVersioningService",
    "HASH_EXCLUDE_FIELDS",
    "BREAKING_CHANGE_FIELDS",
    # Factory functions
    "get_upload_service",
    "get_parser_service",
    "get_security_service",
    "get_deduplication_service",
    "get_dependency_graph",
    "get_inheritance_resolver",
]

# Module initialization logging
logger.debug("Compliance rules module initialized (v%s)", __version__)
