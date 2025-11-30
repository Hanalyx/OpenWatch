"""
Plugin System Module

Provides comprehensive plugin management including registration, execution,
security validation, lifecycle management, analytics, governance, orchestration,
marketplace integration, and development tooling.

Module Architecture:
    plugins/
    +-- __init__.py          # This file - public API and factory functions
    +-- exceptions.py        # Custom exception classes
    +-- registry/            # Plugin CRUD and storage
    +-- security/            # Security validation and signatures
    +-- execution/           # Sandboxed plugin execution (Phase 2)
    +-- import_export/       # Import from files/URLs (Phase 2)
    +-- lifecycle/           # Updates, health, versioning (Phase 3)
    +-- analytics/           # Performance monitoring (Phase 3)
    +-- governance/          # Compliance and audit (Phase 4)
    +-- orchestration/       # Load balancing and scaling (Phase 4)
    +-- marketplace/         # External marketplace integration (Phase 5)
    +-- development/         # SDK and testing framework (Phase 5)

Phase 1 Components (Foundation):
    - PluginRegistryService: Plugin registration, storage, and lifecycle
    - PluginSecurityService: Multi-layered security validation
    - PluginSignatureService: Cryptographic signature verification

Phase 2 Components (Execution + Import):
    - PluginExecutionService: Secure, sandboxed plugin execution
    - PluginImportService: Import plugins from files and URLs

Phase 3 Components (Lifecycle + Analytics):
    - PluginLifecycleService: Zero-downtime updates, health monitoring, rollback
    - PluginAnalyticsService: Performance metrics, usage stats, recommendations

Phase 4 Components (Governance + Orchestration):
    - PluginGovernanceService: Policy management, compliance, audit trails
    - PluginOrchestrationService: Load balancing, auto-scaling, circuit breakers

Phase 5 Components (Marketplace + Development):
    - PluginMarketplaceService: Multi-marketplace discovery, installation, ratings
    - PluginDevelopmentFramework: Validation, testing, benchmarking, templates

Usage:
    # Plugin registration and management
    from backend.app.services.plugins import PluginRegistryService

    registry = PluginRegistryService()
    plugin = await registry.get_plugin("my-plugin@1.0.0")

    # Security validation
    from backend.app.services.plugins import PluginSecurityService

    security = PluginSecurityService()
    is_valid, checks, package = await security.validate_plugin_package(data)

    # Signature verification
    from backend.app.services.plugins import PluginSignatureService

    signature = PluginSignatureService()
    result = await signature.verify_plugin_signature(package)

    # Plugin execution (Phase 2)
    from backend.app.services.plugins import PluginExecutionService

    executor = PluginExecutionService()
    result = await executor.execute_plugin(request)

    # Plugin import (Phase 2)
    from backend.app.services.plugins import PluginImportService

    importer = PluginImportService()
    result = await importer.import_plugin_from_file(content, filename, user_id)

    # Plugin lifecycle (Phase 3)
    from backend.app.services.plugins import PluginLifecycleService

    lifecycle = PluginLifecycleService()
    health = await lifecycle.check_plugin_health("my-plugin@1.0.0")

    # Plugin analytics (Phase 3)
    from backend.app.services.plugins import PluginAnalyticsService

    analytics = PluginAnalyticsService()
    stats = await analytics.generate_usage_stats("my-plugin@1.0.0")

    # Plugin governance (Phase 4)
    from backend.app.services.plugins import PluginGovernanceService

    governance = PluginGovernanceService()
    report = await governance.generate_compliance_report("my-plugin@1.0.0")

    # Plugin orchestration (Phase 4)
    from backend.app.services.plugins import PluginOrchestrationService

    orchestrator = PluginOrchestrationService()
    response = await orchestrator.route_request("my-plugin@1.0.0", "POST", "/scan")

    # Plugin marketplace (Phase 5)
    from backend.app.services.plugins import PluginMarketplaceService

    marketplace = PluginMarketplaceService()
    await marketplace.initialize_marketplace_service()
    results = await marketplace.search_plugins(MarketplaceSearchQuery(query="scanner"))

    # Plugin development (Phase 5)
    from backend.app.services.plugins import PluginDevelopmentFramework

    framework = PluginDevelopmentFramework()
    validation = await framework.validate_plugin_package("/path/to/plugin")
"""

from .analytics.models import (
    AggregationPeriod,
    MetricType,
    OptimizationRecommendation,
    OptimizationRecommendationType,
    PluginMetric,
    PluginMetricSummary,
    PluginPerformanceReport,
    PluginUsageStats,
    SystemWideAnalytics,
)
from .analytics.service import PluginAnalyticsService
from .development.models import (
    BenchmarkConfig,
    BenchmarkResult,
    BenchmarkType,
    PluginPackageInfo,
    TestCase,
    TestEnvironmentType,
    TestExecution,
    TestResult,
    TestStatus,
    TestSuite,
    ValidationResult,
    ValidationSeverity,
)
from .development.service import PluginDevelopmentFramework
from .exceptions import (
    PluginDependencyError,
    PluginError,
    PluginExecutionError,
    PluginImportError,
    PluginNotFoundError,
    PluginRegistryError,
    PluginSecurityError,
    PluginSignatureError,
    PluginValidationError,
)
from .execution.service import PluginExecutionService
from .governance.models import (
    AuditEvent,
    AuditEventType,
    ComplianceReport,
    ComplianceStandard,
    PluginGovernanceConfig,
    PluginPolicy,
    PolicyEnforcementLevel,
    PolicyType,
    PolicyViolation,
    ViolationSeverity,
)
from .governance.service import PluginGovernanceService
from .import_export.importer import PluginImportService
from .lifecycle.models import (
    PluginHealthCheck,
    PluginHealthStatus,
    PluginRollbackPlan,
    PluginUpdateExecution,
    PluginUpdatePlan,
    PluginVersion,
    UpdateStatus,
    UpdateStrategy,
)
from .lifecycle.service import PluginLifecycleService
from .marketplace.models import (
    MarketplaceConfig,
    MarketplacePlugin,
    MarketplaceSearchQuery,
    MarketplaceSearchResult,
    MarketplaceType,
    PluginInstallationRequest,
    PluginInstallationResult,
    PluginRating,
    PluginSource,
)
from .marketplace.service import PluginMarketplaceService
from .orchestration.models import (
    CircuitBreakerConfig,
    CircuitState,
    InstanceStatus,
    OptimizationJob,
    OptimizationTarget,
    OrchestrationStrategy,
    PluginCluster,
    PluginInstance,
    PluginOrchestrationConfig,
    RouteRequest,
    RouteResponse,
    ScalingConfig,
    ScalingPolicy,
)
from .orchestration.service import PluginOrchestrationService
from .registry.service import PluginRegistryService
from .security.signature import PluginSignatureService
from .security.validator import PluginSecurityService

# =============================================================================
# Import exception classes
# =============================================================================


# =============================================================================
# Import service classes (Phase 1: Foundation)
# =============================================================================


# =============================================================================
# Import service classes (Phase 2: Execution + Import)
# =============================================================================


# =============================================================================
# Import service classes (Phase 3: Lifecycle + Analytics)
# =============================================================================


# =============================================================================
# Import service classes (Phase 4: Governance + Orchestration)
# =============================================================================


# =============================================================================
# Import service classes (Phase 5: Marketplace + Development)
# =============================================================================


# =============================================================================
# TYPE_CHECKING imports for type hints
# =============================================================================

# Note: TYPE_CHECKING block reserved for future type hint imports
# Currently all type hints use runtime-available imports


# =============================================================================
# Factory functions (Phase 1)
# =============================================================================


def get_registry_service() -> PluginRegistryService:
    """
    Factory function to create plugin registry service.

    Returns:
        Configured PluginRegistryService instance.

    Example:
        >>> registry = get_registry_service()
        >>> plugin = await registry.get_plugin("my-plugin@1.0.0")
    """
    return PluginRegistryService()


def get_security_service() -> PluginSecurityService:
    """
    Factory function to create plugin security service.

    Returns:
        Configured PluginSecurityService instance.

    Example:
        >>> security = get_security_service()
        >>> is_valid, checks, package = await security.validate_plugin_package(data)
    """
    return PluginSecurityService()


def get_signature_service() -> PluginSignatureService:
    """
    Factory function to create plugin signature service.

    Returns:
        Configured PluginSignatureService instance.

    Example:
        >>> signature = get_signature_service()
        >>> result = await signature.verify_plugin_signature(package)
    """
    return PluginSignatureService()


# =============================================================================
# Factory functions (Phase 2)
# =============================================================================


def get_execution_service() -> PluginExecutionService:
    """
    Factory function to create plugin execution service.

    Returns:
        Configured PluginExecutionService instance.

    Example:
        >>> executor = get_execution_service()
        >>> result = await executor.execute_plugin(request)
    """
    return PluginExecutionService()


def get_import_service() -> PluginImportService:
    """
    Factory function to create plugin import service.

    Returns:
        Configured PluginImportService instance.

    Example:
        >>> importer = get_import_service()
        >>> result = await importer.import_plugin_from_file(content, filename, user_id)
    """
    return PluginImportService()


# =============================================================================
# Factory functions (Phase 3)
# =============================================================================


def get_lifecycle_service() -> PluginLifecycleService:
    """
    Factory function to create plugin lifecycle service.

    Returns:
        Configured PluginLifecycleService instance.

    Example:
        >>> lifecycle = get_lifecycle_service()
        >>> health = await lifecycle.check_plugin_health("my-plugin@1.0.0")
    """
    return PluginLifecycleService()


def get_analytics_service() -> PluginAnalyticsService:
    """
    Factory function to create plugin analytics service.

    Returns:
        Configured PluginAnalyticsService instance.

    Example:
        >>> analytics = get_analytics_service()
        >>> stats = await analytics.generate_usage_stats("my-plugin@1.0.0")
    """
    return PluginAnalyticsService()


# =============================================================================
# Factory functions (Phase 4)
# =============================================================================


def get_governance_service() -> PluginGovernanceService:
    """
    Factory function to create plugin governance service.

    Returns:
        Configured PluginGovernanceService instance.

    Example:
        >>> governance = get_governance_service()
        >>> report = await governance.generate_compliance_report("my-plugin@1.0.0")
    """
    return PluginGovernanceService()


def get_orchestration_service() -> PluginOrchestrationService:
    """
    Factory function to create plugin orchestration service.

    Returns:
        Configured PluginOrchestrationService instance.

    Example:
        >>> orchestrator = get_orchestration_service()
        >>> response = await orchestrator.route_request("my-plugin@1.0.0", "POST", "/scan")
    """
    return PluginOrchestrationService()


# =============================================================================
# Factory functions (Phase 5)
# =============================================================================


def get_marketplace_service() -> PluginMarketplaceService:
    """
    Factory function to create plugin marketplace service.

    Note: Call initialize_marketplace_service() after creation.

    Returns:
        Configured PluginMarketplaceService instance.

    Example:
        >>> marketplace = get_marketplace_service()
        >>> await marketplace.initialize_marketplace_service()
        >>> results = await marketplace.search_plugins(query)
    """
    return PluginMarketplaceService()


def get_development_framework() -> PluginDevelopmentFramework:
    """
    Factory function to create plugin development framework.

    Returns:
        Configured PluginDevelopmentFramework instance.

    Example:
        >>> framework = get_development_framework()
        >>> validation = await framework.validate_plugin_package("/path/to/plugin")
    """
    return PluginDevelopmentFramework()


# =============================================================================
# Public API exports
# =============================================================================

__all__ = [
    # Factory functions (Phase 1)
    "get_registry_service",
    "get_security_service",
    "get_signature_service",
    # Factory functions (Phase 2)
    "get_execution_service",
    "get_import_service",
    # Factory functions (Phase 3)
    "get_lifecycle_service",
    "get_analytics_service",
    # Factory functions (Phase 4)
    "get_governance_service",
    "get_orchestration_service",
    # Factory functions (Phase 5)
    "get_marketplace_service",
    "get_development_framework",
    # Service classes (Phase 1)
    "PluginRegistryService",
    "PluginSecurityService",
    "PluginSignatureService",
    # Service classes (Phase 2)
    "PluginExecutionService",
    "PluginImportService",
    # Service classes (Phase 3)
    "PluginLifecycleService",
    "PluginAnalyticsService",
    # Service classes (Phase 4)
    "PluginGovernanceService",
    "PluginOrchestrationService",
    # Service classes (Phase 5)
    "PluginMarketplaceService",
    "PluginDevelopmentFramework",
    # Lifecycle models (Phase 3)
    "UpdateStrategy",
    "PluginHealthStatus",
    "UpdateStatus",
    "PluginVersion",
    "PluginHealthCheck",
    "PluginUpdatePlan",
    "PluginUpdateExecution",
    "PluginRollbackPlan",
    # Analytics models (Phase 3)
    "MetricType",
    "AggregationPeriod",
    "OptimizationRecommendationType",
    "PluginMetric",
    "PluginMetricSummary",
    "PluginUsageStats",
    "OptimizationRecommendation",
    "PluginPerformanceReport",
    "SystemWideAnalytics",
    # Governance models (Phase 4)
    "ComplianceStandard",
    "PolicyType",
    "PolicyEnforcementLevel",
    "ViolationSeverity",
    "AuditEventType",
    "PluginPolicy",
    "PolicyViolation",
    "ComplianceReport",
    "AuditEvent",
    "PluginGovernanceConfig",
    # Orchestration models (Phase 4)
    "OrchestrationStrategy",
    "OptimizationTarget",
    "ScalingPolicy",
    "InstanceStatus",
    "CircuitState",
    "PluginInstance",
    "PluginCluster",
    "RouteRequest",
    "RouteResponse",
    "OptimizationJob",
    "ScalingConfig",
    "CircuitBreakerConfig",
    "PluginOrchestrationConfig",
    # Marketplace models (Phase 5)
    "MarketplaceType",
    "PluginSource",
    "PluginRating",
    "MarketplacePlugin",
    "MarketplaceConfig",
    "PluginInstallationRequest",
    "PluginInstallationResult",
    "MarketplaceSearchQuery",
    "MarketplaceSearchResult",
    # Development models (Phase 5)
    "TestEnvironmentType",
    "TestStatus",
    "ValidationSeverity",
    "BenchmarkType",
    "PluginPackageInfo",
    "ValidationResult",
    "TestCase",
    "TestResult",
    "BenchmarkConfig",
    "BenchmarkResult",
    "TestSuite",
    "TestExecution",
    # Exceptions
    "PluginError",
    "PluginNotFoundError",
    "PluginImportError",
    "PluginSecurityError",
    "PluginExecutionError",
    "PluginValidationError",
    "PluginRegistryError",
    "PluginSignatureError",
    "PluginDependencyError",
]
