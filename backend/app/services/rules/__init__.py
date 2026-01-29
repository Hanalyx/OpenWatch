"""
Rules Module - Unified API for compliance rule operations

This module provides a comprehensive API for all compliance rule-related
services in OpenWatch, including rule querying, caching, association
mapping, and targeted scanning.

Architecture Overview:
    The rules module follows a layered architecture:

    1. Service Layer (service.py)
       - Main rule query and retrieval service
       - Platform-based filtering and inheritance
       - Variable resolution and dependency graphs

    2. Cache Layer (cache.py)
       - Distributed Redis caching
       - Multi-tier caching strategies
       - Cache metrics and monitoring

    3. Association Layer (association.py)
       - Rule-to-plugin mappings
       - Semantic analysis for recommendations
       - Framework-based associations

    4. Scanner Layer (scanner.py)
       - Targeted rule scanning
       - Remediation verification
       - Scan history tracking

Design Philosophy:
    - Performance First: Aggressive caching for frequently accessed rules
    - Type Safety: Full type annotations and Pydantic models
    - Async Native: All I/O operations are async
    - OW-REFACTOR-002: Repository Pattern (MANDATORY)

Quick Start:
    from app.services.rules import (
        RuleService,
        RuleCacheService,
        RuleAssociationService,
        RuleSpecificScanner,
        get_rule_service,
    )

    # Initialize rule service
    rule_service = get_rule_service()

    # Query rules for a platform
    rules = await rule_service.get_rules_for_platform("rhel", "8")

    # Scan specific rules
    scanner = RuleSpecificScanner()
    results = await scanner.scan_specific_rules(...)

Module Structure:
    rules/
    ├── __init__.py         # This file - public API
    ├── service.py          # RuleService (querying, filtering)
    ├── cache.py            # RuleCacheService (distributed caching)
    ├── association.py      # RuleAssociationService (plugin mappings)
    └── scanner.py          # RuleSpecificScanner (targeted scanning)

Related Modules:
    - services.framework: Framework mapping and reporting
    - services.compliance_rules: Rule upload and versioning
    - repositories.compliance_repository: MongoDB access layer
    - models.mongo_models: ComplianceRule model

Security Notes:
    - Path injection prevention in scanner operations
    - Identifier sanitization for file operations
    - Redis connection security for caching

Performance Notes:
    - Multi-tier caching with Redis
    - Concurrent rule scanning with ThreadPoolExecutor
    - Batch processing for remote scans
"""

import logging

# =============================================================================
# Association Layer - Plugin Mappings
# =============================================================================
from .association import (  # noqa: F401
    MappingConfidence,
    MappingSource,
    RuleAssociationService,
    RuleMappingRecommendation,
    RulePluginMapping,
    SemanticAnalysisResult,
    create_cis_mappings,
    create_stig_mappings,
)

# =============================================================================
# Cache Layer - Distributed Caching
# =============================================================================
from .cache import (
    CacheEntry,
    CacheMetrics,
    CachePriority,
    CacheStrategy,
    RuleCacheService,
)  # noqa: F401

# =============================================================================
# Service Layer - Rule Querying and Management
# =============================================================================
from .service import ParameterResolution, QueryPriority, RuleService  # noqa: F401

logger = logging.getLogger(__name__)

# =============================================================================
# Scanner Layer - Targeted Rule Scanning (Lazy Import)
# =============================================================================
# NOTE: RuleSpecificScanner uses lazy import to avoid circular dependency
# with engine module. Import it directly from .scanner when needed, or use
# the get_rule_scanner() factory function.
_scanner_module = None


def _get_scanner_class():
    """Lazy import of RuleSpecificScanner to avoid circular dependencies."""
    global _scanner_module
    if _scanner_module is None:
        from . import scanner as _scanner_module
    return _scanner_module.RuleSpecificScanner


class _LazyRuleSpecificScanner:
    """Lazy wrapper for RuleSpecificScanner to enable deferred import."""

    def __new__(cls, *args, **kwargs):
        """Create actual RuleSpecificScanner instance on first use."""
        return _get_scanner_class()(*args, **kwargs)


# Provide RuleSpecificScanner as a lazy wrapper
RuleSpecificScanner = _LazyRuleSpecificScanner

# Version of the rules module API
__version__ = "1.0.0"


# =============================================================================
# Factory Functions
# =============================================================================


def get_rule_service() -> RuleService:
    """
    Get a rule service instance.

    Factory function for creating RuleService instances with proper
    initialization.

    Returns:
        Configured RuleService instance.

    Example:
        >>> rule_service = get_rule_service()
        >>> rules = await rule_service.get_rules_for_platform("rhel", "8")
    """
    return RuleService()


def get_cache_service(
    redis_url: str = "redis://localhost:6379",
    default_ttl: int = 3600,
    max_memory_items: int = 1000,
) -> RuleCacheService:
    """
    Get a rule cache service instance.

    Factory function for creating RuleCacheService instances with
    configurable Redis connection and caching parameters.

    Args:
        redis_url: Redis connection URL
        default_ttl: Default TTL for cached items in seconds
        max_memory_items: Maximum number of items in memory cache

    Returns:
        Configured RuleCacheService instance.

    Example:
        >>> cache = get_cache_service(redis_url="redis://cache:6379")
        >>> await cache.set("rules:rhel8", rules_data)
    """
    return RuleCacheService(
        redis_url=redis_url,
        default_ttl=default_ttl,
        max_memory_items=max_memory_items,
    )


def get_association_service() -> RuleAssociationService:
    """
    Get a rule association service instance.

    Factory function for creating RuleAssociationService instances
    for managing rule-to-plugin mappings.

    Returns:
        Configured RuleAssociationService instance.

    Example:
        >>> assoc_service = get_association_service()
        >>> mappings = await assoc_service.get_mappings_for_rule(rule_id)
    """
    return RuleAssociationService()


def get_rule_scanner(results_dir: str = "/app/data/results/rule_scans") -> RuleSpecificScanner:
    """
    Get a rule-specific scanner instance.

    Factory function for creating RuleSpecificScanner instances
    for targeted rule scanning operations.

    Args:
        results_dir: Directory path for storing scan results

    Returns:
        Configured RuleSpecificScanner instance.

    Example:
        >>> scanner = get_rule_scanner()
        >>> results = await scanner.scan_specific_rules(
        ...     host_id="host-123",
        ...     content_path="/app/data/scap/ssg-rhel8-ds.xml",
        ...     profile_id="stig",
        ...     rule_ids=["rule1", "rule2"]
        ... )
    """
    return RuleSpecificScanner(results_dir=results_dir)


# =============================================================================
# Backward Compatibility Aliases
# =============================================================================

# Legacy imports that may still be used in other parts of the codebase
# These aliases ensure smooth migration

# From rule_service.py
RuleQueryService = RuleService  # Legacy alias

# From rule_cache_service.py
DistributedRuleCache = RuleCacheService  # Legacy alias

# From rule_association_service.py
PluginMappingService = RuleAssociationService  # Legacy alias


# =============================================================================
# Public API
# =============================================================================

# Everything that should be importable from this module
__all__ = [
    # Version
    "__version__",
    # Service layer
    "RuleService",
    "QueryPriority",
    "ParameterResolution",
    # Cache layer
    "RuleCacheService",
    "CacheStrategy",
    "CachePriority",
    "CacheMetrics",
    "CacheEntry",
    # Association layer
    "RuleAssociationService",
    "RulePluginMapping",
    "RuleMappingRecommendation",
    "SemanticAnalysisResult",
    "MappingConfidence",
    "MappingSource",
    "create_stig_mappings",
    "create_cis_mappings",
    # Scanner layer
    "RuleSpecificScanner",
    # Factory functions
    "get_rule_service",
    "get_cache_service",
    "get_association_service",
    "get_rule_scanner",
    # Backward compatibility aliases
    "RuleQueryService",
    "DistributedRuleCache",
    "PluginMappingService",
]

# Module initialization logging
logger.debug("Rules module initialized (v%s)", __version__)
