"""
Content Transformation Module

This module provides transformation services to convert parsed compliance content
into formats suitable for storage and processing. The primary use case is
transforming ParsedContent objects from the parsers module into MongoDB
ComplianceRule documents.

Components:
- MongoDBTransformer: Transforms ParsedContent to MongoDB format
- ContentNormalizer: Cross-format content normalization
- TransformationResult: Result container with statistics
- NormalizationStats: Statistics from normalization operations

Usage:
    from backend.app.services.content.transformation import (
        MongoDBTransformer,
        ContentNormalizer,
        transform_to_mongodb,
        normalize_content,
    )

    # Normalize content first (optional but recommended)
    normalizer = ContentNormalizer()
    normalized = normalizer.normalize_content(parsed_content)

    # Transform parsed content to MongoDB format
    transformer = MongoDBTransformer()
    result = transformer.transform(normalized)
    print(f"Transformed {result.success_count} rules")

    # Convenience function for quick transformation
    rules = transform_to_mongodb(parsed_content)
"""

import logging

from ..models import ParsedContent
from .normalizer import (  # noqa: F401
    ContentNormalizer,
    NormalizationStats,
    clean_text,
    normalize_content,
    normalize_platform,
    normalize_reference,
    normalize_severity,
)
from .transformer import MongoDBTransformer, TransformationResult  # noqa: F401

logger = logging.getLogger(__name__)


def transform_to_mongodb(parsed_content: ParsedContent) -> TransformationResult:
    """
    Transform parsed content to MongoDB ComplianceRule format.

    This is a convenience function that creates a MongoDBTransformer
    and transforms the content in a single call.

    Args:
        parsed_content: ParsedContent object from a parser.

    Returns:
        TransformationResult with transformed rules and statistics.

    Example:
        >>> from backend.app.services.content.parsers import SCAPParser
        >>> from backend.app.services.content.transformation import transform_to_mongodb
        >>>
        >>> parser = SCAPParser()
        >>> content = parser.parse("/path/to/benchmark.xml")
        >>> result = transform_to_mongodb(content)
        >>> print(f"Transformed {result.success_count} rules")
    """
    transformer = MongoDBTransformer()
    return transformer.transform(parsed_content)


# Public API exports
__all__ = [
    # Transformer
    "MongoDBTransformer",
    "TransformationResult",
    "transform_to_mongodb",
    # Normalizer
    "ContentNormalizer",
    "NormalizationStats",
    "normalize_content",
    "normalize_severity",
    "normalize_platform",
    "normalize_reference",
    "clean_text",
]
