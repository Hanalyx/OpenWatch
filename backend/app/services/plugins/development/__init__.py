"""
Plugin Development Subpackage

Provides comprehensive development, testing, validation, and debugging tools
for plugin creation and quality assurance.

Components:
    - PluginDevelopmentFramework: Main service for plugin development
    - Models: Test cases, validation results, benchmarks, suites

Development Capabilities:
    - Plugin package validation and quality analysis
    - Comprehensive testing environments and test execution
    - Performance benchmarking and optimization
    - Code quality assessment and security scanning
    - Development tools and template generation

Test Environment Types:
    - UNIT: Unit testing environment
    - INTEGRATION: Integration testing environment
    - PERFORMANCE: Performance testing environment
    - SECURITY: Security testing environment
    - PRODUCTION_MIRROR: Production-like environment

Benchmark Types:
    - THROUGHPUT: Operations per second
    - LATENCY: Response time
    - MEMORY: Memory usage
    - CPU: CPU utilization
    - SCALABILITY: Load handling capacity

Validation Severities:
    - INFO: Informational note
    - WARNING: Non-critical issue
    - ERROR: Significant problem
    - CRITICAL: Blocking issue

Usage:
    from app.services.plugins.development import PluginDevelopmentFramework

    framework = PluginDevelopmentFramework()

    # Validate a plugin package
    validation = await framework.validate_plugin_package("/path/to/plugin")
    print(f"Validation score: {validation.validation_score}/100")

    # Create and run tests
    suite = await framework.create_test_suite(
        plugin_id="my-plugin",
        name="Integration Tests",
        description="Full integration test suite",
        created_by="developer",
    )
    execution = await framework.execute_test_suite(
        suite_id=suite.suite_id,
        environment_type=TestEnvironmentType.INTEGRATION,
        triggered_by="developer",
    )

Example:
    >>> from app.services.plugins.development import (
    ...     PluginDevelopmentFramework,
    ...     TestEnvironmentType,
    ...     BenchmarkType,
    ... )
    >>> framework = PluginDevelopmentFramework()
    >>> template_path = await framework.generate_plugin_template(
    ...     plugin_name="my_scanner",
    ...     plugin_type="scanner",
    ...     author="Developer",
    ...     output_path="/tmp/plugins",
    ... )
    >>> print(f"Template created at: {template_path}")
"""

from .models import (
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
from .service import PluginDevelopmentFramework

__all__ = [
    # Service
    "PluginDevelopmentFramework",
    # Enums
    "TestEnvironmentType",
    "TestStatus",
    "ValidationSeverity",
    "BenchmarkType",
    # Models
    "PluginPackageInfo",
    "ValidationResult",
    "TestCase",
    "TestResult",
    "BenchmarkConfig",
    "BenchmarkResult",
    "TestSuite",
    "TestExecution",
]
