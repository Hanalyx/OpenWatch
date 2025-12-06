"""
Framework Services Module - Unified API for compliance framework operations

This module provides a comprehensive API for all compliance framework-related
operations in OpenWatch, including mapping, reporting, metadata discovery,
and cross-framework analysis.

Architecture Overview:
    The framework module follows a modular architecture:

    1. Models Layer (models.py)
       - Data structures for scan results, framework results, host results
       - RuleExecution dataclass for individual rule outcomes

    2. Mapping Layer (mapper.py)
       - ComplianceFrameworkMapper: Rule-to-framework mapping
       - Framework inference from SCAP rule IDs
       - Multi-framework compliance matrix generation

    3. Reporting Layer (reporting.py)
       - ComplianceFrameworkReporter: Report generation
       - Gap analysis and remediation roadmaps
       - Executive dashboards and compliance summaries

    4. Engine Layer (engine.py)
       - FrameworkMappingEngine: Cross-framework control mapping
       - Framework relationship analysis
       - Unified implementation generation

    5. Metadata Layer (metadata.py)
       - FrameworkMetadataService: Framework discovery
       - Variable definitions and validation
       - Framework version details

Quick Start:
    from backend.app.services.framework import (
        # Data models
        ScanResult,
        FrameworkResult,
        HostResult,
        RuleExecution,
        # Mapping
        ComplianceFrameworkMapper,
        ComplianceFramework,
        FrameworkMapping,
        ComplianceControl,
        # Reporting
        ComplianceFrameworkReporter,
        # Engine
        FrameworkMappingEngine,
        MappingConfidence,
        MappingType,
        ControlMapping,
        FrameworkRelationship,
        UnifiedImplementation,
        # Metadata
        FrameworkMetadataService,
    )

    # Initialize mapper
    mapper = ComplianceFrameworkMapper()
    mappings = mapper.map_scap_rule_to_frameworks("xccdf_...rule_id...")

    # Initialize reporter
    reporter = ComplianceFrameworkReporter()
    await reporter.initialize()
    report = await reporter.generate_compliance_report(scan_id, db)

    # Initialize engine
    engine = FrameworkMappingEngine()
    mappings = await engine.discover_control_mappings(
        "nist_800_53_r5", "cis_v8", unified_rules
    )

    # Initialize metadata service
    metadata_service = FrameworkMetadataService(db)
    frameworks = await metadata_service.list_frameworks()

Module Structure:
    framework/
    ├── __init__.py           # This file - public API
    ├── models.py             # Data models (ScanResult, FrameworkResult, etc.)
    ├── mapper.py             # ComplianceFrameworkMapper
    ├── reporting.py          # ComplianceFrameworkReporter
    ├── engine.py             # FrameworkMappingEngine
    └── metadata.py           # FrameworkMetadataService

Related Modules:
    - services.compliance_rules: Rule upload and versioning
    - services.owca: Compliance intelligence and scoring
    - repositories.compliance_repository: MongoDB access layer
    - models.scan_config_models: Framework configuration models

Backward Compatibility:
    This module provides aliases for legacy imports:
    - multi_framework_scanner.py -> framework.models
    - compliance_framework_mapper.py -> framework.mapper
    - compliance_framework_reporting.py -> framework.reporting
    - framework_mapping_engine.py -> framework.engine
    - framework_metadata_service.py -> framework.metadata
"""

import logging

# =============================================================================
# Framework Mapping Engine
# =============================================================================
from .engine import (  # noqa: F401
    ControlMapping,
    FrameworkMappingEngine,
    FrameworkRelationship,
    MappingConfidence,
    MappingType,
    UnifiedImplementation,
)

# =============================================================================
# Framework Mapper
# =============================================================================
from .mapper import ComplianceControl, ComplianceFramework, ComplianceFrameworkMapper, FrameworkMapping  # noqa: F401

# =============================================================================
# Framework Metadata Service
# =============================================================================
from .metadata import FrameworkMetadataService  # noqa: F401

# =============================================================================
# Data Models
# =============================================================================
from .models import FrameworkResult, HostResult, RuleExecution, ScanResult  # noqa: F401

# =============================================================================
# Framework Reporting
# =============================================================================
from .reporting import ComplianceFrameworkReporter  # noqa: F401

logger = logging.getLogger(__name__)

# Version of the framework module API
__version__ = "1.0.0"


# =============================================================================
# Factory Functions
# =============================================================================


def get_framework_mapper() -> ComplianceFrameworkMapper:
    """
    Get a compliance framework mapper instance.

    Factory function for creating ComplianceFrameworkMapper instances.

    Returns:
        Configured ComplianceFrameworkMapper instance.

    Example:
        >>> mapper = get_framework_mapper()
        >>> mappings = mapper.map_scap_rule_to_frameworks(rule_id)
    """
    return ComplianceFrameworkMapper()


def get_mapping_engine() -> FrameworkMappingEngine:
    """
    Get a framework mapping engine instance.

    Factory function for creating FrameworkMappingEngine instances.

    Returns:
        Configured FrameworkMappingEngine instance.

    Example:
        >>> engine = get_mapping_engine()
        >>> await engine.load_predefined_mappings(mappings_file)
    """
    return FrameworkMappingEngine()


def get_framework_reporter() -> ComplianceFrameworkReporter:
    """
    Get a compliance framework reporter instance.

    Factory function for creating ComplianceFrameworkReporter instances.
    Note: Requires async initialization via reporter.initialize().

    Returns:
        ComplianceFrameworkReporter instance (requires initialization).

    Example:
        >>> reporter = get_framework_reporter()
        >>> await reporter.initialize()
        >>> report = await reporter.generate_compliance_report(scan_id, db)
    """
    return ComplianceFrameworkReporter()


# =============================================================================
# Backward Compatibility Aliases
# =============================================================================

# Legacy: multi_framework_scanner.py
MultiFrameworkScanResult = ScanResult
MultiFrameworkResult = FrameworkResult
MultiFrameworkHostResult = HostResult

# Legacy: framework_mapping_engine.py
# Classes are exported directly, no aliases needed

# Legacy: Alternative naming for reporter
FrameworkReportingService = ComplianceFrameworkReporter

# =============================================================================
# Public API
# =============================================================================

__all__ = [
    # Version
    "__version__",
    # Data Models
    "RuleExecution",
    "FrameworkResult",
    "HostResult",
    "ScanResult",
    # Mapper
    "ComplianceFramework",
    "FrameworkMapping",
    "ComplianceControl",
    "ComplianceFrameworkMapper",
    # Reporting
    "ComplianceFrameworkReporter",
    # Engine
    "MappingConfidence",
    "MappingType",
    "ControlMapping",
    "FrameworkRelationship",
    "UnifiedImplementation",
    "FrameworkMappingEngine",
    # Metadata
    "FrameworkMetadataService",
    # Factory functions
    "get_framework_mapper",
    "get_mapping_engine",
    "get_framework_reporter",
    # Backward compatibility aliases
    "MultiFrameworkScanResult",
    "MultiFrameworkResult",
    "MultiFrameworkHostResult",
    "FrameworkReportingService",
]

# Module initialization logging
logger.debug("Framework services module initialized (v%s)", __version__)
