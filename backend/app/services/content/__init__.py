"""
Content Processing Module - Unified API for compliance content operations

This module provides a comprehensive, unified API for all compliance content
processing operations in OpenWatch. It consolidates parsing, transformation,
import, and validation capabilities into a single, well-documented interface.

Architecture Overview:
    The content module follows a layered architecture:

    1. Parsers Layer (content.parsers)
       - Reads raw content files (XCCDF, SCAP datastreams)
       - Produces ParsedContent objects with normalized data
       - Handles format detection and validation

    2. Transformation Layer (content.transformation)
       - Converts ParsedContent to MongoDB document format
       - Applies framework mappings (NIST, CIS, STIG)
       - Generates platform implementations

    3. Import Layer (content.import)
       - Orchestrates bulk import to MongoDB
       - Handles batching and progress tracking
       - Manages deduplication strategies
       - Validates dependencies before transfer

Design Philosophy:
    - Single Responsibility: Each submodule handles one aspect of content processing
    - Immutable Data: ParsedContent, ParsedRule, etc. are frozen dataclasses
    - Type Safety: Full type annotations for IDE support and runtime validation
    - Security-First: XXE prevention, path validation, input sanitization
    - Defensive Coding: Graceful error handling with detailed exceptions

Supported Content Formats:
    - XCCDF 1.1 and 1.2 benchmarks (via SCAPParser)
    - SCAP 1.2 and 1.3 datastreams (via DatastreamParser)
    - OVAL definitions (extracted from SCAP content)
    - CPE dictionaries (for platform mapping)
    - Tailoring files (future support)

Quick Start:
    # Parse a SCAP datastream
    from backend.app.services.content import parse_content, ContentFormat

    content = parse_content("/path/to/ssg-rhel8-ds.xml")
    print(f"Parsed {len(content.rules)} rules from {content.source_file}")

    # Transform to MongoDB format
    from backend.app.services.content import transform_to_mongodb

    result = transform_to_mongodb(content)
    print(f"Transformed {result.rules_transformed} rules")

    # Import to MongoDB
    from backend.app.services.content import ContentImporter

    importer = ContentImporter(db)
    result = await importer.import_rules(result.rules)
    print(f"Imported {result.imported_count} rules")

    # Validate dependencies for remote transfer
    from backend.app.services.content import DependencyValidator

    validator = DependencyValidator()
    deps = validator.resolve("/path/to/xccdf.xml")
    files = validator.get_transfer_list()

Module Structure:
    content/
    ├── __init__.py          # This file - public API
    ├── models.py            # Shared data models (ParsedRule, ParsedContent, etc.)
    ├── exceptions.py        # Content-specific exceptions
    ├── parsers/             # Content parsing
    │   ├── __init__.py      # Parser registry and factory
    │   ├── base.py          # Abstract base parser
    │   ├── scap.py          # XCCDF parser
    │   └── datastream.py    # SCAP datastream parser
    ├── transformation/      # MongoDB transformation
    │   ├── __init__.py      # Transformer exports
    │   └── transformer.py   # MongoDBTransformer
    └── import/              # MongoDB import
        ├── __init__.py      # Import exports
        ├── importer.py      # ContentImporter
        └── validator.py     # DependencyValidator

Related Modules:
    - services.owca: Compliance intelligence and scoring
    - services.scap_scanner: SCAP execution on remote hosts
    - repositories.compliance_repository: MongoDB access layer
    - models.mongo_models: ComplianceRule Beanie model

Security Notes:
    - Uses defusedxml for XXE prevention
    - Validates all file paths to prevent directory traversal
    - Limits file sizes to prevent DoS attacks
    - Sanitizes error messages to prevent information disclosure

Performance Notes:
    - Batch imports use configurable chunk sizes (default 100)
    - Progress callbacks enable real-time UI updates
    - Lazy loading for large datastream components
    - Redis caching available for frequently accessed rules

Usage Examples:
    See docstrings in individual classes and functions for detailed examples.
    Integration tests in tests/integration/test_content_module.py provide
    end-to-end workflow examples.
"""

import logging
from typing import Callable, Optional

# Re-export exceptions for error handling
# These provide detailed context about content processing failures
from .exceptions import (
    ContentError,
    ContentImportError,
    ContentParseError,
    ContentTransformationError,
    ContentValidationError,
    UnsupportedFormatError,
)

# Re-export import components
from .import_ import (
    ContentImporter,
    DependencyValidator,
    ImportProgress,
    ImportResult,
    SCAPDependency,
)

# Re-export models for convenient access
# These are the core data structures used throughout content processing
from .models import (
    ContentFormat,
    ContentSeverity,
    ContentValidationResult,
    DependencyResolution,
    ImportStage,
    ParsedContent,
    ParsedOVALDefinition,
    ParsedProfile,
    ParsedRule,
)

# Re-export parsers - these read raw content files
from .parsers import (
    BaseContentParser,
    DatastreamParser,
    SCAPParser,
    get_parser_for_format,
    get_supported_formats,
    parse_content,
    register_parser,
)

# Re-export transformation components
from .transformation import (
    ContentNormalizer,
    MongoDBTransformer,
    NormalizationStats,
    TransformationResult,
    clean_text,
    normalize_content,
    normalize_platform,
    normalize_reference,
    normalize_severity,
    transform_to_mongodb,
)

logger = logging.getLogger(__name__)

# Version of the content module API
__version__ = "1.0.0"

# =============================================================================
# Backward Compatibility Aliases
# =============================================================================
# These aliases maintain compatibility with legacy import paths.
# New code should use the canonical names directly.

# Legacy parser service aliases
SCAPParserService = SCAPParser  # Legacy: scap_parser_service.py
DataStreamProcessor = DatastreamParser  # Legacy: scap_datastream_processor.py
SCAPDataStreamProcessor = DatastreamParser  # Legacy: alternate name

# Legacy transformation service aliases
SCAPTransformationService = MongoDBTransformer  # Legacy: scap_transformation_service.py
ContentTransformer = MongoDBTransformer  # Generic name

# Legacy import service aliases
SCAPImportService = ContentImporter  # Legacy: scap_import_service.py

# Legacy validator aliases
SCAPDependencyResolver = DependencyValidator  # Legacy: scap_dependency_resolver.py
ContentValidator = DependencyValidator  # Generic name


# =============================================================================
# Factory Functions
# =============================================================================


def get_parser(content_format: ContentFormat) -> BaseContentParser:
    """
    Get a parser instance for the specified content format.

    This factory function returns the appropriate parser based on the
    content format. It's the recommended way to get parsers when the
    format is determined at runtime.

    Args:
        content_format: The ContentFormat enum value.

    Returns:
        Parser instance appropriate for the format.

    Raises:
        UnsupportedFormatError: If no parser supports the format.

    Example:
        >>> parser = get_parser(ContentFormat.SCAP_DATASTREAM)
        >>> content = parser.parse("/path/to/ssg-rhel8-ds.xml")
    """
    parser = get_parser_for_format(content_format)
    if parser is None:
        raise UnsupportedFormatError(
            message=f"No parser available for format: {content_format.value}",
            detected_format=content_format.value,
            supported_formats=[f.value for f in get_supported_formats()],
        )
    return parser


def get_importer(db=None) -> ContentImporter:
    """
    Get a content importer instance.

    Factory function for creating ContentImporter instances with
    optional database connection.

    Args:
        db: Optional database connection. If None, uses default.

    Returns:
        Configured ContentImporter instance.

    Example:
        >>> importer = get_importer()
        >>> result = await importer.import_rules(transformed_rules)
    """
    return ContentImporter(db)


def get_transformer() -> MongoDBTransformer:
    """
    Get a content transformer instance.

    Factory function for creating MongoDBTransformer instances.

    Returns:
        Configured MongoDBTransformer instance.

    Example:
        >>> transformer = get_transformer()
        >>> result = transformer.transform(parsed_content)
    """
    return MongoDBTransformer()


def get_normalizer() -> ContentNormalizer:
    """
    Get a content normalizer instance.

    Factory function for creating ContentNormalizer instances.

    Returns:
        Configured ContentNormalizer instance.

    Example:
        >>> normalizer = get_normalizer()
        >>> normalized = normalizer.normalize_content(parsed_content)
    """
    return ContentNormalizer()


def get_validator() -> DependencyValidator:
    """
    Get a dependency validator instance.

    Factory function for creating DependencyValidator instances.

    Returns:
        Configured DependencyValidator instance.

    Example:
        >>> validator = get_validator()
        >>> deps = validator.resolve("/path/to/xccdf.xml")
    """
    return DependencyValidator()


# Public API - everything that should be importable from this module
__all__ = [
    # Version
    "__version__",
    # Models
    "ContentFormat",
    "ContentSeverity",
    "ContentValidationResult",
    "DependencyResolution",
    "ImportStage",
    "ParsedContent",
    "ParsedOVALDefinition",
    "ParsedProfile",
    "ParsedRule",
    # Exceptions
    "ContentError",
    "ContentParseError",
    "ContentValidationError",
    "ContentTransformationError",
    "ContentImportError",
    "UnsupportedFormatError",
    # Parsers
    "BaseContentParser",
    "SCAPParser",
    "DatastreamParser",
    "register_parser",
    "get_parser_for_format",
    "get_supported_formats",
    "parse_content",
    # Transformation
    "MongoDBTransformer",
    "TransformationResult",
    "transform_to_mongodb",
    # Normalization
    "ContentNormalizer",
    "NormalizationStats",
    "normalize_content",
    "normalize_severity",
    "normalize_platform",
    "normalize_reference",
    "clean_text",
    # Import
    "ContentImporter",
    "ImportProgress",
    "ImportResult",
    "DependencyValidator",
    "SCAPDependency",
    # Factory functions
    "get_parser",
    "get_importer",
    "get_transformer",
    "get_normalizer",
    "get_validator",
    # Convenience functions
    "process_scap_content",
    # Backward compatibility aliases
    "SCAPParserService",
    "DataStreamProcessor",
    "SCAPDataStreamProcessor",
    "SCAPTransformationService",
    "ContentTransformer",
    "SCAPImportService",
    "SCAPDependencyResolver",
    "ContentValidator",
]


def process_scap_content(
    source_path: str,
    db=None,
    progress_callback: Optional[Callable[[ImportProgress], None]] = None,
    batch_size: int = 100,
    deduplication: str = "skip_existing",
) -> ImportResult:
    """
    High-level convenience function for end-to-end SCAP content processing.

    This function provides a simple one-call interface for the complete
    content processing workflow: parse -> transform -> import. Use this
    for straightforward imports; for more control, use the individual
    components directly.

    Workflow:
        1. Parse SCAP content file (auto-detects format)
        2. Transform to MongoDB ComplianceRule format
        3. Import to MongoDB with deduplication

    Args:
        source_path: Path to SCAP content file (XCCDF or datastream).
        db: MongoDB database connection. If None, creates default connection.
        progress_callback: Optional callback for progress updates.
        batch_size: Number of rules per import batch (default 100).
        deduplication: Strategy for handling existing rules:
            - "skip_existing": Skip rules that already exist (default)
            - "update_existing": Update existing rules with new data
            - "replace_all": Delete existing and replace with new

    Returns:
        ImportResult with statistics about the import operation.

    Raises:
        ContentParseError: If content cannot be parsed.
        ContentTransformationError: If transformation fails.
        ContentImportError: If database import fails.
        FileNotFoundError: If source file doesn't exist.

    Example:
        >>> result = process_scap_content(
        ...     "/app/scap/ssg-rhel8-ds.xml",
        ...     progress_callback=lambda p: print(f"{p.percent_complete}%"),
        ... )
        >>> print(f"Imported {result.imported_count} rules")

    Note:
        For complex workflows (custom transformation, validation, etc.),
        use the individual components:
        - parse_content() or specific parsers
        - MongoDBTransformer.transform()
        - ContentImporter.import_rules()
    """
    logger.info("Starting SCAP content processing: %s", source_path)

    # Step 1: Parse content (auto-detects format)
    logger.debug("Step 1/3: Parsing content")
    parsed_content = parse_content(source_path)
    logger.info(
        "Parsed %d rules from %s",
        len(parsed_content.rules),
        parsed_content.source_file,
    )

    # Step 2: Transform to MongoDB format
    logger.debug("Step 2/3: Transforming to MongoDB format")
    transformer = MongoDBTransformer()
    transform_result = transformer.transform(parsed_content)
    logger.info(
        "Transformed %d rules (skipped %d)",
        transform_result.rules_transformed,
        transform_result.rules_skipped,
    )

    # Step 3: Import to MongoDB
    logger.debug("Step 3/3: Importing to MongoDB")

    # Create importer with provided or default database
    importer = ContentImporter(db)

    # Import with progress tracking
    import_result = importer.import_rules(
        rules=transform_result.rules,
        progress_callback=progress_callback,
        batch_size=batch_size,
        deduplication_strategy=deduplication,
    )

    logger.info(
        "Import complete: %d imported, %d updated, %d skipped, %d failed",
        import_result.imported_count,
        import_result.updated_count,
        import_result.skipped_count,
        import_result.failed_count,
    )

    return import_result


# Module initialization logging
logger.debug("Content processing module initialized (v%s)", __version__)
