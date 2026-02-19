"""
Content Transformation Module

This module provides transformation services to convert parsed compliance content
into normalized formats suitable for storage and processing.

Components:
- ContentNormalizer: Cross-format content normalization
- NormalizationStats: Statistics from normalization operations

Usage:
    from app.services.content.transformation import (
        ContentNormalizer,
        normalize_content,
    )

    # Normalize content
    normalizer = ContentNormalizer()
    normalized = normalizer.normalize_content(parsed_content)
"""

import logging

from .normalizer import (  # noqa: F401
    ContentNormalizer,
    NormalizationStats,
    clean_text,
    normalize_content,
    normalize_platform,
    normalize_reference,
    normalize_severity,
)

logger = logging.getLogger(__name__)


# Public API exports
__all__ = [
    # Normalizer
    "ContentNormalizer",
    "NormalizationStats",
    "normalize_content",
    "normalize_severity",
    "normalize_platform",
    "normalize_reference",
    "clean_text",
]
