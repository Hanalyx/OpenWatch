"""
XCCDF Generation Module - Generate XCCDF 1.2 Content from MongoDB Rules

This module provides a comprehensive API for generating XCCDF (Extensible
Configuration Checklist Description Format) compliant XML from MongoDB
compliance rules.

Architecture Overview:
    The xccdf module follows a single-responsibility principle:
    - XCCDFGeneratorService: Core generation logic for XCCDF 1.2 XML

    This is conceptually the INVERSE of the content/ module:
    - content/ = Parse SCAP files -> Transform -> Import to MongoDB
    - xccdf/   = Read MongoDB -> Generate XCCDF XML output

Design Philosophy:
    - XCCDF 1.2 Compliance: Follows NIST SP 7275 Rev 4 specification
    - Platform-Aware: Phase 3 platform-specific OVAL selection
    - Component Filtering: Exclude inapplicable rules for target systems
    - XML Security: Uses defusedxml patterns for safe parsing

Supported Output Formats:
    - XCCDF 1.2 Benchmarks (full checklist documents)
    - XCCDF 1.2 Tailoring files (variable customization)
    - Aggregated OVAL definitions files

Quick Start:
    from backend.app.services.xccdf import XCCDFGeneratorService

    # Initialize with MongoDB connection
    generator = XCCDFGeneratorService(mongo_db)

    # Generate benchmark for specific framework
    xml_content = await generator.generate_benchmark(
        benchmark_id="openwatch-nist-800-53r5",
        title="NIST 800-53 Rev 5 Benchmark",
        description="OpenWatch generated benchmark for NIST compliance",
        version="1.0.0",
        framework="nist",
        framework_version="800-53r5",
        target_platform="rhel9",  # Platform-aware OVAL selection
    )

    # Generate tailoring file for variable customization
    tailoring_xml = await generator.generate_tailoring(
        tailoring_id="openwatch-tailoring-001",
        benchmark_href="benchmark.xml",
        benchmark_version="1.0.0",
        profile_id="xccdf_com.hanalyx.openwatch_profile_nist_800_53r5",
        variable_overrides={
            "var_accounts_tmout": "900",
            "var_password_minlen": "14",
        },
    )

Module Structure:
    xccdf/
    ├── __init__.py     # This file - public API
    └── generator.py    # XCCDFGeneratorService implementation

Related Modules:
    - services.content: SCAP parsing and MongoDB import (inverse operation)
    - services.engine: SCAP scan execution
    - services.owca.extraction: XCCDF result parsing
    - repositories.compliance_repository: MongoDB access layer

Security Notes:
    - Uses ElementTree with nosec comments for trusted content
    - Validates all file paths for OVAL definitions
    - XML output is well-formed and XCCDF 1.2 schema-compliant

Performance Notes:
    - Lazy OVAL file reading (only when needed)
    - Efficient MongoDB queries with framework filtering
    - Component-based rule filtering for reduced output size

XCCDF 1.2 Specification:
    https://csrc.nist.gov/publications/detail/nistir/7275/rev-4/final
"""

import logging

# Core generator service
from .generator import XCCDFGeneratorService

logger = logging.getLogger(__name__)

# Version of the XCCDF generation module API
__version__ = "1.0.0"


# =============================================================================
# Factory Functions
# =============================================================================


def get_xccdf_generator(db) -> XCCDFGeneratorService:
    """
    Get an XCCDF generator instance.

    Factory function for creating XCCDFGeneratorService instances.

    Args:
        db: MongoDB database connection (Motor AsyncIOMotorDatabase).

    Returns:
        Configured XCCDFGeneratorService instance.

    Example:
        >>> from motor.motor_asyncio import AsyncIOMotorClient
        >>> client = AsyncIOMotorClient("mongodb://localhost:27017")
        >>> db = client.openwatch_rules
        >>> generator = get_xccdf_generator(db)
        >>> xml = await generator.generate_benchmark(...)
    """
    return XCCDFGeneratorService(db)


# =============================================================================
# Backward Compatibility Alias
# =============================================================================

# Legacy import path support
# from backend.app.services.xccdf_generator_service import XCCDFGeneratorService
# is now:
# from backend.app.services.xccdf import XCCDFGeneratorService


# Public API - everything that should be importable from this module
__all__ = [
    # Version
    "__version__",
    # Core service
    "XCCDFGeneratorService",
    # Factory functions
    "get_xccdf_generator",
]

# Module initialization logging
logger.debug("XCCDF generation module initialized (v%s)", __version__)
