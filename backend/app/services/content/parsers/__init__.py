"""
Content Parsers Module

This module provides parsers for various compliance content formats including
SCAP datastreams, XCCDF benchmarks, OVAL definitions, and future support for
CIS Benchmarks, DISA STIGs, and custom formats.

Available Parsers:
- BaseContentParser: Abstract base class for all parsers
- SCAPParser: SCAP/XCCDF content parser
- DatastreamParser: SCAP 1.3 datastream parser

Usage:
    from app.services.content.parsers import (
        SCAPParser,
        DatastreamParser,
        get_parser_for_format,
    )

    # Parse a SCAP datastream
    parser = DatastreamParser()
    content = parser.parse("/path/to/ssg-rhel8-ds.xml")

    # Auto-detect format and get appropriate parser
    parser = get_parser_for_format(ContentFormat.SCAP_DATASTREAM)
"""

import logging
from typing import Dict, Optional, Type

from ..exceptions import UnsupportedFormatError
from ..models import ContentFormat
from .base import BaseContentParser  # noqa: F401

logger = logging.getLogger(__name__)

# Parser registry - maps formats to parser classes
# Populated when parsers are imported
_parser_registry: Dict[ContentFormat, Type[BaseContentParser]] = {}


def register_parser(parser_class: Type[BaseContentParser]) -> Type[BaseContentParser]:
    """
    Register a parser class for its supported formats.

    This decorator registers a parser in the global registry, allowing
    automatic parser selection based on content format.

    Args:
        parser_class: The parser class to register.

    Returns:
        The same parser class (allows use as decorator).

    Example:
        @register_parser
        class SCAPParser(BaseContentParser):
            ...
    """
    # Create an instance to get supported formats
    # This is safe because parsers should be lightweight and stateless
    try:
        instance = parser_class()
        for content_format in instance.supported_formats:
            if content_format in _parser_registry:
                logger.warning(
                    "Overwriting parser registration for format %s: %s -> %s",
                    content_format.value,
                    _parser_registry[content_format].__name__,
                    parser_class.__name__,
                )
            _parser_registry[content_format] = parser_class
            logger.debug(
                "Registered parser %s for format %s",
                parser_class.__name__,
                content_format.value,
            )
    except Exception as e:
        logger.error(
            "Failed to register parser %s: %s",
            parser_class.__name__,
            str(e),
        )

    return parser_class


def get_parser_for_format(
    content_format: ContentFormat,
) -> Optional[BaseContentParser]:
    """
    Get a parser instance for the specified content format.

    Args:
        content_format: The ContentFormat to get a parser for.

    Returns:
        Parser instance or None if no parser supports the format.
    """
    parser_class = _parser_registry.get(content_format)
    if parser_class:
        return parser_class()
    return None


def get_supported_formats() -> list:
    """
    Get list of all supported content formats.

    Returns:
        List of ContentFormat values that have registered parsers.
    """
    return list(_parser_registry.keys())


def parse_content(
    source,
    content_format: Optional[ContentFormat] = None,
):
    """
    Parse content using the appropriate parser.

    This is a convenience function that auto-selects the parser based
    on the content format.

    Args:
        source: Content source (file path, bytes, or file-like object).
        content_format: Optional format hint. If not provided, format
                       detection will be attempted.

    Returns:
        ParsedContent object.

    Raises:
        UnsupportedFormatError: If no parser supports the format.
        ContentParseError: If parsing fails.
    """
    # Try to detect format if not provided
    if content_format is None:
        # Use first registered parser's detection
        for parser_class in _parser_registry.values():
            parser = parser_class()
            try:
                return parser.parse(source, content_format=None)
            except UnsupportedFormatError:
                continue
        raise UnsupportedFormatError(
            message="Could not detect content format and no suitable parser found",
            supported_formats=[f.value for f in get_supported_formats()],
        )

    # Get parser for format
    parser = get_parser_for_format(content_format)
    if parser is None:
        raise UnsupportedFormatError(
            message=f"No parser registered for format: {content_format.value}",
            detected_format=content_format.value,
            supported_formats=[f.value for f in get_supported_formats()],
        )

    return parser.parse(source, content_format=content_format)


# Import parsers to trigger registration
# These imports are at the bottom to avoid circular imports
from .datastream import DatastreamParser  # noqa: F401, E402
from .scap import SCAPParser  # noqa: F401, E402

# Public API exports
__all__ = [
    # Base class
    "BaseContentParser",
    # Registry functions
    "register_parser",
    "get_parser_for_format",
    "get_supported_formats",
    "parse_content",
    # Concrete parsers
    "SCAPParser",
    "DatastreamParser",
]
