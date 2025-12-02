"""
Content Import Module

This module provides services for importing parsed and transformed compliance
content into MongoDB. It handles bulk import operations with progress tracking,
deduplication, dependency validation, and integrity verification.

Components:
- ContentImporter: Main import service for bulk rule import
- DependencyValidator: Validates content dependencies before import
- ImportProgress: Progress tracking for long-running imports
- ImportResult: Result container with statistics

Usage:
    from backend.app.services.content.import_ import (
        ContentImporter,
        DependencyValidator,
        ImportProgress,
    )

    # Import transformed rules
    importer = ContentImporter(mongo_service)
    result = await importer.import_rules(transformed_rules)
    print(f"Imported {result.imported_count} rules")

    # Validate dependencies
    validator = DependencyValidator()
    deps = validator.resolve("/path/to/benchmark.xml")
    errors = validator.validate()
"""

import logging

from .importer import ContentImporter, ImportProgress, ImportResult  # noqa: F401
from .validator import DependencyValidator, SCAPDependency  # noqa: F401

logger = logging.getLogger(__name__)


# Public API exports
__all__ = [
    # Import service
    "ContentImporter",
    "ImportProgress",
    "ImportResult",
    # Dependency validation
    "DependencyValidator",
    "SCAPDependency",
]
