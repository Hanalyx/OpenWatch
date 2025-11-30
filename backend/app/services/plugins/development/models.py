"""
Plugin Development Models

Defines data models, enumerations, and schemas for the plugin development
and testing framework including test cases, validation results, benchmarks,
and execution tracking.

This module follows OpenWatch security and documentation standards:
- All models use Pydantic for validation and serialization
- Beanie Documents for MongoDB persistence where needed
- Comprehensive type hints for IDE support
- Defensive validation with constraints

Security Considerations:
- Validation scores bounded to prevent manipulation
- Test execution tracking enables audit trails
- Benchmark results stored for comparison
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from beanie import Document
from pydantic import BaseModel, Field

# ============================================================================
# DEVELOPMENT FRAMEWORK ENUMERATIONS
# ============================================================================


class TestEnvironmentType(str, Enum):
    """
    Types of test environments for plugin testing.

    Each environment type provides different testing capabilities
    and isolation levels for comprehensive plugin validation.

    Attributes:
        UNIT: Isolated unit testing environment for component tests
        INTEGRATION: Integration testing with mocked dependencies
        PERFORMANCE: Performance testing with load generation
        SECURITY: Security testing with vulnerability scanning
        PRODUCTION_MIRROR: Production-like environment for final validation
    """

    UNIT = "unit"
    INTEGRATION = "integration"
    PERFORMANCE = "performance"
    SECURITY = "security"
    PRODUCTION_MIRROR = "production_mirror"


class TestStatus(str, Enum):
    """
    Test execution status values.

    Tracks the lifecycle of test execution from pending through
    completion with various outcome states.

    Attributes:
        PENDING: Test is queued but not started
        RUNNING: Test is currently executing
        PASSED: Test completed successfully
        FAILED: Test completed with assertion failures
        SKIPPED: Test was skipped (dependencies not met, etc.)
        ERROR: Test encountered an error during execution
    """

    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


class ValidationSeverity(str, Enum):
    """
    Validation issue severity levels.

    Used to classify issues found during plugin package validation
    to help prioritize remediation efforts.

    Attributes:
        INFO: Informational note, no action required
        WARNING: Non-critical issue that should be addressed
        ERROR: Significant problem that affects functionality
        CRITICAL: Blocking issue that prevents plugin use
    """

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class BenchmarkType(str, Enum):
    """
    Types of performance benchmarks.

    Each benchmark type measures a different aspect of plugin
    performance to ensure quality and reliability.

    Attributes:
        THROUGHPUT: Operations per second measurement
        LATENCY: Response time measurement
        MEMORY: Memory usage measurement
        CPU: CPU utilization measurement
        SCALABILITY: Load handling capacity measurement
    """

    THROUGHPUT = "throughput"
    LATENCY = "latency"
    MEMORY = "memory"
    CPU = "cpu"
    SCALABILITY = "scalability"


# ============================================================================
# PACKAGE AND VALIDATION MODELS
# ============================================================================


class PluginPackageInfo(BaseModel):
    """
    Information about a plugin package.

    Captures metadata about a plugin package for validation,
    installation, and dependency management.

    Attributes:
        name: Plugin package name
        version: Package version string
        description: Package description
        author: Package author
        license: License identifier
        python_version: Required Python version constraint
        dependencies: Runtime dependencies
        dev_dependencies: Development dependencies
        plugin_type: Type of plugin (scanner, remediation, etc.)
        entry_point: Main entry point file
        supported_platforms: List of supported platforms
        repository_url: Source code repository URL
        documentation_url: Documentation URL
        bug_tracker_url: Bug tracker URL
    """

    name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Plugin package name",
    )
    version: str = Field(
        ...,
        description="Package version string (semver preferred)",
    )
    description: str = Field(
        ...,
        max_length=1000,
        description="Package description",
    )
    author: str = Field(
        ...,
        max_length=255,
        description="Package author",
    )
    license: str = Field(
        ...,
        max_length=50,
        description="License identifier (e.g., MIT, Apache-2.0)",
    )

    # Python environment requirements
    python_version: str = Field(
        default=">=3.8",
        description="Required Python version constraint",
    )
    dependencies: List[str] = Field(
        default_factory=list,
        description="Runtime dependencies (pip format)",
    )
    dev_dependencies: List[str] = Field(
        default_factory=list,
        description="Development dependencies (pip format)",
    )

    # Plugin metadata
    plugin_type: str = Field(
        ...,
        description="Type of plugin (scanner, remediation, etc.)",
    )
    entry_point: str = Field(
        ...,
        description="Main entry point file (e.g., plugin.py)",
    )
    supported_platforms: List[str] = Field(
        default_factory=list,
        description="List of supported platforms (linux, windows, macos)",
    )

    # Development and support URLs
    repository_url: Optional[str] = Field(
        default=None,
        description="Source code repository URL",
    )
    documentation_url: Optional[str] = Field(
        default=None,
        description="Documentation URL",
    )
    bug_tracker_url: Optional[str] = Field(
        default=None,
        description="Bug tracker URL",
    )


class ValidationResult(BaseModel):
    """
    Result of plugin package validation.

    Comprehensive validation results including scores, issue breakdown,
    and recommendations for improvement.

    Attributes:
        is_valid: Whether the plugin passed validation
        validation_score: Overall validation score (0-100)
        info_count: Number of informational notes
        warning_count: Number of warnings
        error_count: Number of errors
        critical_count: Number of critical issues
        issues: Detailed list of validation issues
        code_quality_score: Code quality sub-score (0-100)
        security_score: Security assessment sub-score (0-100)
        performance_score: Performance indicators sub-score (0-100)
        recommendations: List of improvement recommendations
    """

    is_valid: bool = Field(
        ...,
        description="Whether the plugin passed validation",
    )
    validation_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Overall validation score (0-100)",
    )

    # Issue counts by severity
    info_count: int = Field(
        default=0,
        ge=0,
        description="Number of informational notes",
    )
    warning_count: int = Field(
        default=0,
        ge=0,
        description="Number of warnings",
    )
    error_count: int = Field(
        default=0,
        ge=0,
        description="Number of errors",
    )
    critical_count: int = Field(
        default=0,
        ge=0,
        description="Number of critical issues",
    )

    # Detailed issues
    issues: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Detailed list of validation issues",
    )

    # Quality sub-scores
    code_quality_score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Code quality sub-score (0-100)",
    )
    security_score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Security assessment sub-score (0-100)",
    )
    performance_score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Performance indicators sub-score (0-100)",
    )

    # Recommendations for improvement
    recommendations: List[str] = Field(
        default_factory=list,
        description="List of improvement recommendations",
    )


# ============================================================================
# TEST CASE AND RESULT MODELS
# ============================================================================


class TestCase(BaseModel):
    """
    Individual test case definition.

    Defines a single test case with setup, execution, and teardown
    commands along with expected results.

    Attributes:
        test_id: Unique test case identifier
        name: Human-readable test name
        description: Test case description
        test_type: Type of test environment required
        setup_commands: Commands to run before test
        test_commands: Commands that execute the test
        teardown_commands: Commands to run after test
        expected_return_code: Expected exit code (0 for success)
        expected_outputs: Expected output strings
        timeout_seconds: Maximum execution time
        depends_on: List of test IDs that must pass first
        requires_resources: Required resources (database, network, etc.)
    """

    test_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique test case identifier",
    )
    name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Human-readable test name",
    )
    description: str = Field(
        ...,
        max_length=1000,
        description="Test case description",
    )
    test_type: TestEnvironmentType = Field(
        ...,
        description="Type of test environment required",
    )

    # Test commands
    setup_commands: List[str] = Field(
        default_factory=list,
        description="Commands to run before test",
    )
    test_commands: List[str] = Field(
        default_factory=list,
        description="Commands that execute the test",
    )
    teardown_commands: List[str] = Field(
        default_factory=list,
        description="Commands to run after test",
    )

    # Expected results
    expected_return_code: int = Field(
        default=0,
        ge=0,
        description="Expected exit code (0 for success)",
    )
    expected_outputs: List[str] = Field(
        default_factory=list,
        description="Expected output strings",
    )
    timeout_seconds: int = Field(
        default=300,
        ge=1,
        le=3600,
        description="Maximum execution time (1s - 1h)",
    )

    # Dependencies
    depends_on: List[str] = Field(
        default_factory=list,
        description="List of test IDs that must pass first",
    )
    requires_resources: List[str] = Field(
        default_factory=list,
        description="Required resources (database, network, etc.)",
    )


class TestResult(BaseModel):
    """
    Result of test case execution.

    Captures detailed execution results including timing, output,
    assertions, and performance metrics.

    Attributes:
        test_id: ID of the executed test case
        test_name: Name of the executed test
        status: Test execution status
        started_at: Execution start timestamp
        completed_at: Execution completion timestamp
        duration_seconds: Total execution duration
        return_code: Actual exit code
        stdout: Standard output captured
        stderr: Standard error captured
        assertions_passed: Number of passed assertions
        assertions_failed: Number of failed assertions
        assertion_details: Detailed assertion results
        error_message: Error message if failed
        stack_trace: Stack trace if error occurred
        memory_usage_mb: Memory usage during execution
        cpu_usage_percent: CPU usage during execution
        execution_time_ms: Precise execution time
    """

    test_id: str = Field(
        ...,
        description="ID of the executed test case",
    )
    test_name: str = Field(
        ...,
        description="Name of the executed test",
    )
    status: TestStatus = Field(
        ...,
        description="Test execution status",
    )

    # Execution timing
    started_at: datetime = Field(
        ...,
        description="Execution start timestamp",
    )
    completed_at: Optional[datetime] = Field(
        default=None,
        description="Execution completion timestamp",
    )
    duration_seconds: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Total execution duration in seconds",
    )

    # Execution output
    return_code: Optional[int] = Field(
        default=None,
        description="Actual exit code",
    )
    stdout: Optional[str] = Field(
        default=None,
        description="Standard output captured",
    )
    stderr: Optional[str] = Field(
        default=None,
        description="Standard error captured",
    )

    # Assertion tracking
    assertions_passed: int = Field(
        default=0,
        ge=0,
        description="Number of passed assertions",
    )
    assertions_failed: int = Field(
        default=0,
        ge=0,
        description="Number of failed assertions",
    )
    assertion_details: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Detailed assertion results",
    )

    # Error information
    error_message: Optional[str] = Field(
        default=None,
        description="Error message if failed",
    )
    stack_trace: Optional[str] = Field(
        default=None,
        description="Stack trace if error occurred",
    )

    # Performance metrics
    memory_usage_mb: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Memory usage during execution in MB",
    )
    cpu_usage_percent: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=100.0,
        description="CPU usage during execution",
    )
    execution_time_ms: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Precise execution time in milliseconds",
    )


# ============================================================================
# BENCHMARK MODELS
# ============================================================================


class BenchmarkConfig(BaseModel):
    """
    Configuration for performance benchmarking.

    Defines parameters for benchmark execution including load
    configuration, resource limits, and success criteria.

    Attributes:
        benchmark_type: Type of benchmark to run
        duration_seconds: Benchmark duration (10s - 1h)
        concurrent_requests: Number of concurrent requests
        request_rate: Target requests per second
        test_data_sets: Test data set identifiers
        input_variations: Input parameter variations
        memory_limit_mb: Memory limit for benchmark
        cpu_limit_percent: CPU limit for benchmark
        min_throughput: Minimum acceptable throughput
        max_latency_ms: Maximum acceptable latency
        max_memory_mb: Maximum acceptable memory usage
    """

    benchmark_type: BenchmarkType = Field(
        ...,
        description="Type of benchmark to run",
    )
    duration_seconds: int = Field(
        default=60,
        ge=10,
        le=3600,
        description="Benchmark duration (10s - 1h)",
    )

    # Load configuration
    concurrent_requests: int = Field(
        default=10,
        ge=1,
        le=1000,
        description="Number of concurrent requests",
    )
    request_rate: Optional[int] = Field(
        default=None,
        ge=1,
        description="Target requests per second",
    )

    # Test data
    test_data_sets: List[str] = Field(
        default_factory=list,
        description="Test data set identifiers",
    )
    input_variations: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Input parameter variations",
    )

    # Resource limits
    memory_limit_mb: Optional[int] = Field(
        default=None,
        ge=1,
        description="Memory limit for benchmark in MB",
    )
    cpu_limit_percent: Optional[int] = Field(
        default=None,
        ge=1,
        le=100,
        description="CPU limit for benchmark",
    )

    # Success criteria
    min_throughput: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Minimum acceptable throughput (ops/sec)",
    )
    max_latency_ms: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Maximum acceptable latency in ms",
    )
    max_memory_mb: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Maximum acceptable memory usage in MB",
    )


class BenchmarkResult(BaseModel):
    """
    Result of performance benchmark execution.

    Captures comprehensive benchmark results including performance
    metrics, resource usage, and comparison with baselines.

    Attributes:
        benchmark_type: Type of benchmark executed
        config: Benchmark configuration used
        started_at: Benchmark start timestamp
        completed_at: Benchmark completion timestamp
        duration_seconds: Actual duration
        throughput_ops_per_sec: Measured throughput
        avg_latency_ms: Average latency
        p95_latency_ms: 95th percentile latency
        p99_latency_ms: 99th percentile latency
        avg_memory_mb: Average memory usage
        peak_memory_mb: Peak memory usage
        avg_cpu_percent: Average CPU usage
        peak_cpu_percent: Peak CPU usage
        success_rate: Successful operation rate (0-1)
        error_count: Number of errors during benchmark
        timeout_count: Number of timeouts during benchmark
        baseline_comparison: Comparison with baseline results
        meets_criteria: Whether benchmark meets success criteria
    """

    benchmark_type: BenchmarkType = Field(
        ...,
        description="Type of benchmark executed",
    )
    config: BenchmarkConfig = Field(
        ...,
        description="Benchmark configuration used",
    )

    # Timing
    started_at: datetime = Field(
        ...,
        description="Benchmark start timestamp",
    )
    completed_at: datetime = Field(
        ...,
        description="Benchmark completion timestamp",
    )
    duration_seconds: float = Field(
        ...,
        ge=0.0,
        description="Actual duration in seconds",
    )

    # Performance metrics
    throughput_ops_per_sec: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Measured throughput (operations per second)",
    )
    avg_latency_ms: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Average latency in milliseconds",
    )
    p95_latency_ms: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="95th percentile latency in milliseconds",
    )
    p99_latency_ms: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="99th percentile latency in milliseconds",
    )

    # Resource usage
    avg_memory_mb: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Average memory usage in MB",
    )
    peak_memory_mb: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Peak memory usage in MB",
    )
    avg_cpu_percent: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=100.0,
        description="Average CPU usage percentage",
    )
    peak_cpu_percent: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=100.0,
        description="Peak CPU usage percentage",
    )

    # Success metrics
    success_rate: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Successful operation rate (0-1)",
    )
    error_count: int = Field(
        default=0,
        ge=0,
        description="Number of errors during benchmark",
    )
    timeout_count: int = Field(
        default=0,
        ge=0,
        description="Number of timeouts during benchmark",
    )

    # Comparison and evaluation
    baseline_comparison: Optional[Dict[str, float]] = Field(
        default=None,
        description="Comparison with baseline results",
    )
    meets_criteria: bool = Field(
        default=False,
        description="Whether benchmark meets success criteria",
    )


# ============================================================================
# TEST SUITE DOCUMENTS (MongoDB)
# ============================================================================


class TestSuite(Document):
    """
    Complete test suite for a plugin (MongoDB Document).

    Persisted test suite definition including test cases,
    execution settings, and quality gates.

    Attributes:
        suite_id: Unique test suite identifier
        plugin_id: ID of the plugin under test
        name: Human-readable suite name
        description: Suite description
        test_cases: List of test cases in suite
        test_environments: Supported test environments
        parallel_execution: Whether tests can run in parallel
        continue_on_failure: Whether to continue after failure
        timeout_minutes: Maximum suite execution time
        minimum_coverage: Required code coverage percentage
        minimum_success_rate: Required test success rate
        created_by: User who created the suite
        created_at: Suite creation timestamp
        updated_at: Last update timestamp
    """

    suite_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique test suite identifier",
    )
    plugin_id: str = Field(
        ...,
        description="ID of the plugin under test",
    )
    name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Human-readable suite name",
    )
    description: str = Field(
        ...,
        max_length=2000,
        description="Suite description",
    )

    # Test configuration
    test_cases: List[TestCase] = Field(
        default_factory=list,
        description="List of test cases in suite",
    )
    test_environments: List[TestEnvironmentType] = Field(
        default_factory=list,
        description="Supported test environments",
    )

    # Execution settings
    parallel_execution: bool = Field(
        default=True,
        description="Whether tests can run in parallel",
    )
    continue_on_failure: bool = Field(
        default=True,
        description="Whether to continue after failure",
    )
    timeout_minutes: int = Field(
        default=60,
        ge=1,
        le=1440,
        description="Maximum suite execution time (1min - 24h)",
    )

    # Quality gates
    minimum_coverage: float = Field(
        default=80.0,
        ge=0.0,
        le=100.0,
        description="Required code coverage percentage",
    )
    minimum_success_rate: float = Field(
        default=95.0,
        ge=0.0,
        le=100.0,
        description="Required test success rate percentage",
    )

    # Metadata
    created_by: str = Field(
        ...,
        description="User who created the suite",
    )
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Suite creation timestamp",
    )
    updated_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Last update timestamp",
    )

    class Settings:
        """Beanie settings for MongoDB collection configuration."""

        name = "plugin_test_suites"
        indexes = [
            "suite_id",
            "plugin_id",
            "created_by",
        ]


class TestExecution(Document):
    """
    Test suite execution record (MongoDB Document).

    Persisted record of a test suite execution including
    individual test results and aggregate statistics.

    Attributes:
        execution_id: Unique execution identifier
        suite_id: ID of the executed test suite
        plugin_id: ID of the plugin under test
        environment_type: Test environment used
        triggered_by: User who triggered execution
        execution_context: Additional execution context
        overall_status: Overall execution status
        test_results: Individual test results
        total_tests: Total number of tests
        passed_tests: Number of passed tests
        failed_tests: Number of failed tests
        skipped_tests: Number of skipped tests
        error_tests: Number of errored tests
        code_coverage: Code coverage percentage achieved
        success_rate: Test success rate achieved
        started_at: Execution start timestamp
        completed_at: Execution completion timestamp
        duration_seconds: Total execution duration
        log_files: Paths to log files
        coverage_reports: Paths to coverage reports
        benchmark_results: Performance benchmark results
    """

    execution_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique execution identifier",
    )
    suite_id: str = Field(
        ...,
        description="ID of the executed test suite",
    )
    plugin_id: str = Field(
        ...,
        description="ID of the plugin under test",
    )

    # Execution configuration
    environment_type: TestEnvironmentType = Field(
        ...,
        description="Test environment used",
    )
    triggered_by: str = Field(
        ...,
        description="User who triggered execution",
    )
    execution_context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional execution context",
    )

    # Results
    overall_status: TestStatus = Field(
        default=TestStatus.PENDING,
        description="Overall execution status",
    )
    test_results: List[TestResult] = Field(
        default_factory=list,
        description="Individual test results",
    )

    # Summary statistics
    total_tests: int = Field(
        default=0,
        ge=0,
        description="Total number of tests",
    )
    passed_tests: int = Field(
        default=0,
        ge=0,
        description="Number of passed tests",
    )
    failed_tests: int = Field(
        default=0,
        ge=0,
        description="Number of failed tests",
    )
    skipped_tests: int = Field(
        default=0,
        ge=0,
        description="Number of skipped tests",
    )
    error_tests: int = Field(
        default=0,
        ge=0,
        description="Number of errored tests",
    )

    # Quality metrics
    code_coverage: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=100.0,
        description="Code coverage percentage achieved",
    )
    success_rate: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Test success rate percentage",
    )

    # Timing
    started_at: Optional[datetime] = Field(
        default=None,
        description="Execution start timestamp",
    )
    completed_at: Optional[datetime] = Field(
        default=None,
        description="Execution completion timestamp",
    )
    duration_seconds: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Total execution duration in seconds",
    )

    # Artifacts
    log_files: List[str] = Field(
        default_factory=list,
        description="Paths to log files",
    )
    coverage_reports: List[str] = Field(
        default_factory=list,
        description="Paths to coverage reports",
    )

    # Benchmarking
    benchmark_results: List[BenchmarkResult] = Field(
        default_factory=list,
        description="Performance benchmark results",
    )

    class Settings:
        """Beanie settings for MongoDB collection configuration."""

        name = "plugin_test_executions"
        indexes = [
            "execution_id",
            "suite_id",
            "plugin_id",
            "started_at",
            "overall_status",
        ]
