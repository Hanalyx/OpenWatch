"""
Content Processing Module - Unified API for compliance content operations

This module provides a comprehensive, unified API for all compliance content
processing operations in OpenWatch. It consolidates parsing, transformation,
and validation capabilities into a single, well-documented interface.

Architecture Overview:
    The content module follows a layered architecture:

    1. Parsers Layer (content.parsers)
       - Reads raw content files (XCCDF, SCAP datastreams)
       - Produces ParsedContent objects with normalized data
       - Handles format detection and validation

    2. Transformation Layer (content.transformation)
       - Applies content normalization
       - Generates platform implementations

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
    from app.services.content import parse_content, ContentFormat

    content = parse_content("/path/to/ssg-rhel8-ds.xml")
    print(f"Parsed {len(content.rules)} rules from {content.source_file}")

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
    └── transformation/      # Content normalization
        ├── __init__.py      # Normalizer exports
        └── normalizer.py    # ContentNormalizer

Related Modules:
    - services.owca: Compliance intelligence and scoring
    - services.engine: Scan execution

Security Notes:
    - Uses defusedxml for XXE prevention
    - Validates all file paths to prevent directory traversal
    - Limits file sizes to prevent DoS attacks
    - Sanitizes error messages to prevent information disclosure

Performance Notes:
    - Lazy loading for large datastream components
    - Redis caching available for frequently accessed rules

Usage Examples:
    See docstrings in individual classes and functions for detailed examples.
    Integration tests in tests/integration/test_content_module.py provide
    end-to-end workflow examples.
"""

import logging

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
    NormalizationStats,
    clean_text,
    normalize_content,
    normalize_platform,
    normalize_reference,
    normalize_severity,
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
    # Normalization
    "ContentNormalizer",
    "NormalizationStats",
    "normalize_content",
    "normalize_severity",
    "normalize_platform",
    "normalize_reference",
    "clean_text",
    # Factory functions
    "get_parser",
    "get_normalizer",
    # Backward compatibility aliases
    "SCAPParserService",
    "DataStreamProcessor",
    "SCAPDataStreamProcessor",
]


# Module initialization logging
logger.debug("Content processing module initialized (v%s)", __version__)
