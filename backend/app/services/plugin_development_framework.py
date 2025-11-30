"""
Plugin Development and Testing Framework
Provides comprehensive tools for plugin development, testing, validation, and debugging.
Includes SDK components, testing environments, and quality assurance features.
"""

import ast
import asyncio
import json
import logging
import tempfile
import traceback
import uuid
import zipfile
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from beanie import Document
from pydantic import BaseModel, Field

from ..models.plugin_models import InstalledPlugin
from .plugin_execution_service import PluginExecutionService
from .plugin_registry_service import PluginRegistryService

logger = logging.getLogger(__name__)


# ============================================================================
# DEVELOPMENT FRAMEWORK MODELS AND ENUMS
# ============================================================================


class TestEnvironmentType(str, Enum):
    """Types of test environments"""

    UNIT = "unit"  # Unit testing environment
    INTEGRATION = "integration"  # Integration testing environment
    PERFORMANCE = "performance"  # Performance testing environment
    SECURITY = "security"  # Security testing environment
    PRODUCTION_MIRROR = "production_mirror"  # Production-like environment


class TestStatus(str, Enum):
    """Test execution status"""

    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


class ValidationSeverity(str, Enum):
    """Validation issue severity levels"""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class BenchmarkType(str, Enum):
    """Types of performance benchmarks"""

    THROUGHPUT = "throughput"  # Operations per second
    LATENCY = "latency"  # Response time
    MEMORY = "memory"  # Memory usage
    CPU = "cpu"  # CPU utilization
    SCALABILITY = "scalability"  # Load handling capacity


class PluginPackageInfo(BaseModel):
    """Information about a plugin package"""

    name: str
    version: str
    description: str
    author: str
    license: str

    # Dependencies
    python_version: str = Field(default=">=3.8")
    dependencies: List[str] = Field(default_factory=list)
    dev_dependencies: List[str] = Field(default_factory=list)

    # Plugin metadata
    plugin_type: str
    entry_point: str
    supported_platforms: List[str] = Field(default_factory=list)

    # Development info
    repository_url: Optional[str] = None
    documentation_url: Optional[str] = None
    bug_tracker_url: Optional[str] = None


class ValidationResult(BaseModel):
    """Result of plugin validation"""

    is_valid: bool
    validation_score: float = Field(..., ge=0.0, le=100.0)

    # Issue breakdown
    info_count: int = 0
    warning_count: int = 0
    error_count: int = 0
    critical_count: int = 0

    # Detailed issues
    issues: List[Dict[str, Any]] = Field(default_factory=list)

    # Quality metrics
    code_quality_score: float = Field(default=0.0, ge=0.0, le=100.0)
    security_score: float = Field(default=0.0, ge=0.0, le=100.0)
    performance_score: float = Field(default=0.0, ge=0.0, le=100.0)

    # Recommendations
    recommendations: List[str] = Field(default_factory=list)


class TestCase(BaseModel):
    """Individual test case definition"""

    test_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    test_type: TestEnvironmentType

    # Test configuration
    setup_commands: List[str] = Field(default_factory=list)
    test_commands: List[str] = Field(default_factory=list)
    teardown_commands: List[str] = Field(default_factory=list)

    # Expected results
    expected_return_code: int = Field(default=0)
    expected_outputs: List[str] = Field(default_factory=list)
    timeout_seconds: int = Field(default=300)

    # Dependencies
    depends_on: List[str] = Field(default_factory=list)
    requires_resources: List[str] = Field(default_factory=list)


class TestResult(BaseModel):
    """Result of test case execution"""

    test_id: str
    test_name: str
    status: TestStatus

    # Execution details
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None

    # Results
    return_code: Optional[int] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None

    # Assertions
    assertions_passed: int = 0
    assertions_failed: int = 0
    assertion_details: List[Dict[str, Any]] = Field(default_factory=list)

    # Error information
    error_message: Optional[str] = None
    stack_trace: Optional[str] = None

    # Performance metrics
    memory_usage_mb: Optional[float] = None
    cpu_usage_percent: Optional[float] = None
    execution_time_ms: Optional[float] = None


class BenchmarkConfig(BaseModel):
    """Configuration for performance benchmarking"""

    benchmark_type: BenchmarkType
    duration_seconds: int = Field(default=60, ge=10, le=3600)

    # Load configuration
    concurrent_requests: int = Field(default=10, ge=1, le=1000)
    request_rate: Optional[int] = None  # Requests per second

    # Test data
    test_data_sets: List[str] = Field(default_factory=list)
    input_variations: List[Dict[str, Any]] = Field(default_factory=list)

    # Resource limits
    memory_limit_mb: Optional[int] = None
    cpu_limit_percent: Optional[int] = None

    # Success criteria
    min_throughput: Optional[float] = None
    max_latency_ms: Optional[float] = None
    max_memory_mb: Optional[float] = None


class BenchmarkResult(BaseModel):
    """Result of performance benchmark"""

    benchmark_type: BenchmarkType
    config: BenchmarkConfig

    # Execution details
    started_at: datetime
    completed_at: datetime
    duration_seconds: float

    # Performance metrics
    throughput_ops_per_sec: Optional[float] = None
    avg_latency_ms: Optional[float] = None
    p95_latency_ms: Optional[float] = None
    p99_latency_ms: Optional[float] = None

    # Resource usage
    avg_memory_mb: Optional[float] = None
    peak_memory_mb: Optional[float] = None
    avg_cpu_percent: Optional[float] = None
    peak_cpu_percent: Optional[float] = None

    # Success metrics
    success_rate: float = Field(..., ge=0.0, le=1.0)
    error_count: int = 0
    timeout_count: int = 0

    # Comparison
    baseline_comparison: Optional[Dict[str, float]] = None
    meets_criteria: bool = Field(default=False)


class TestSuite(Document):
    """Complete test suite for a plugin"""

    suite_id: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True)
    plugin_id: str
    name: str
    description: str

    # Test configuration
    test_cases: List[TestCase] = Field(default_factory=list)
    test_environments: List[TestEnvironmentType] = Field(default_factory=list)

    # Execution settings
    parallel_execution: bool = Field(default=True)
    continue_on_failure: bool = Field(default=True)
    timeout_minutes: int = Field(default=60)

    # Quality gates
    minimum_coverage: float = Field(default=80.0, ge=0.0, le=100.0)
    minimum_success_rate: float = Field(default=95.0, ge=0.0, le=100.0)

    # Metadata
    created_by: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        collection = "plugin_test_suites"
        indexes = ["suite_id", "plugin_id", "created_by"]


class TestExecution(Document):
    """Test suite execution record"""

    execution_id: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True)
    suite_id: str
    plugin_id: str

    # Execution configuration
    environment_type: TestEnvironmentType
    triggered_by: str
    execution_context: Dict[str, Any] = Field(default_factory=dict)

    # Results
    overall_status: TestStatus = TestStatus.PENDING
    test_results: List[TestResult] = Field(default_factory=list)

    # Summary statistics
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    skipped_tests: int = 0
    error_tests: int = 0

    # Quality metrics
    code_coverage: Optional[float] = None
    success_rate: float = 0.0

    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None

    # Artifacts
    log_files: List[str] = Field(default_factory=list)
    coverage_reports: List[str] = Field(default_factory=list)

    # Benchmarking (if applicable)
    benchmark_results: List[BenchmarkResult] = Field(default_factory=list)

    class Settings:
        collection = "plugin_test_executions"
        indexes = [
            "execution_id",
            "suite_id",
            "plugin_id",
            "started_at",
            "overall_status",
        ]


# ============================================================================
# PLUGIN DEVELOPMENT FRAMEWORK SERVICE
# ============================================================================


class PluginDevelopmentFramework:
    """
    Comprehensive plugin development and testing framework

    Provides:
    - Plugin package validation and quality analysis
    - Comprehensive testing environments and test execution
    - Performance benchmarking and optimization
    - Code quality assessment and security scanning
    - Development tools and debugging support
    """

    def __init__(self) -> None:
        self.plugin_registry_service = PluginRegistryService()
        self.plugin_execution_service = PluginExecutionService()
        self.test_environments: Dict[str, Dict[str, Any]] = {}
        self.active_tests: Dict[str, TestExecution] = {}
        self.benchmark_baselines: Dict[str, BenchmarkResult] = {}

    async def validate_plugin_package(self, package_path: str) -> ValidationResult:
        """Comprehensive validation of a plugin package"""

        validation_result = ValidationResult(is_valid=True, validation_score=100.0)

        try:
            package_path_obj = Path(package_path)

            # Extract package if it's a zip file
            if package_path_obj.suffix == ".zip":
                temp_dir = tempfile.mkdtemp()
                try:
                    with zipfile.ZipFile(package_path, "r") as zip_ref:
                        zip_ref.extractall(temp_dir)
                    package_path_obj = Path(temp_dir)
                except Exception as e:
                    validation_result.issues.append(
                        {
                            "severity": ValidationSeverity.CRITICAL,
                            "type": "package_extraction",
                            "message": f"Failed to extract package: {str(e)}",
                        }
                    )
                    validation_result.is_valid = False
                    validation_result.critical_count += 1
                    return validation_result

            # Validate package structure
            await self._validate_package_structure(package_path_obj, validation_result)

            # Validate plugin manifest
            await self._validate_plugin_manifest(package_path_obj, validation_result)

            # Validate Python code quality
            await self._validate_code_quality(package_path_obj, validation_result)

            # Security validation
            await self._validate_security(package_path_obj, validation_result)

            # Performance validation
            await self._validate_performance_indicators(package_path_obj, validation_result)

            # Calculate final scores
            self._calculate_validation_scores(validation_result)

        except Exception as e:
            logger.error(f"Plugin validation failed: {e}")
            validation_result.issues.append(
                {
                    "severity": ValidationSeverity.CRITICAL,
                    "type": "validation_error",
                    "message": f"Validation process failed: {str(e)}",
                }
            )
            validation_result.is_valid = False
            validation_result.critical_count += 1

        logger.info(f"Plugin validation completed: {validation_result.validation_score:.1f}/100")
        return validation_result

    async def create_test_suite(
        self,
        plugin_id: str,
        name: str,
        description: str,
        created_by: str,
        test_cases: List[TestCase] = None,
    ) -> TestSuite:
        """Create a comprehensive test suite for a plugin"""

        if test_cases is None:
            test_cases = await self._generate_default_test_cases(plugin_id)

        test_suite = TestSuite(
            plugin_id=plugin_id,
            name=name,
            description=description,
            test_cases=test_cases,
            test_environments=[
                TestEnvironmentType.UNIT,
                TestEnvironmentType.INTEGRATION,
                TestEnvironmentType.PERFORMANCE,
            ],
            created_by=created_by,
        )

        await test_suite.save()

        logger.info(f"Created test suite: {test_suite.suite_id} for plugin {plugin_id}")
        return test_suite

    async def execute_test_suite(
        self,
        suite_id: str,
        environment_type: TestEnvironmentType,
        triggered_by: str,
        execution_context: Dict[str, Any] = None,
    ) -> TestExecution:
        """Execute a test suite in the specified environment"""

        test_suite = await TestSuite.find_one(TestSuite.suite_id == suite_id)
        if not test_suite:
            raise ValueError(f"Test suite not found: {suite_id}")

        if execution_context is None:
            execution_context = {}

        execution = TestExecution(
            suite_id=suite_id,
            plugin_id=test_suite.plugin_id,
            environment_type=environment_type,
            triggered_by=triggered_by,
            execution_context=execution_context,
            total_tests=len(test_suite.test_cases),
        )

        await execution.save()
        self.active_tests[execution.execution_id] = execution

        # Start test execution asynchronously
        asyncio.create_task(self._execute_test_suite_async(test_suite, execution))

        logger.info(f"Started test suite execution: {execution.execution_id}")
        return execution

    async def run_performance_benchmark(
        self,
        plugin_id: str,
        benchmark_config: BenchmarkConfig,
        baseline_comparison: bool = True,
    ) -> BenchmarkResult:
        """Run performance benchmark for a plugin"""

        plugin = await self.plugin_registry_service.get_plugin(plugin_id)
        if not plugin:
            raise ValueError(f"Plugin not found: {plugin_id}")

        started_at = datetime.utcnow()

        # Execute benchmark based on type
        if benchmark_config.benchmark_type == BenchmarkType.THROUGHPUT:
            result = await self._benchmark_throughput(plugin, benchmark_config)
        elif benchmark_config.benchmark_type == BenchmarkType.LATENCY:
            result = await self._benchmark_latency(plugin, benchmark_config)
        elif benchmark_config.benchmark_type == BenchmarkType.MEMORY:
            result = await self._benchmark_memory(plugin, benchmark_config)
        elif benchmark_config.benchmark_type == BenchmarkType.CPU:
            result = await self._benchmark_cpu(plugin, benchmark_config)
        elif benchmark_config.benchmark_type == BenchmarkType.SCALABILITY:
            result = await self._benchmark_scalability(plugin, benchmark_config)
        else:
            raise ValueError(f"Unsupported benchmark type: {benchmark_config.benchmark_type}")

        completed_at = datetime.utcnow()
        duration = (completed_at - started_at).total_seconds()

        benchmark_result = BenchmarkResult(
            benchmark_type=benchmark_config.benchmark_type,
            config=benchmark_config,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            **result,
        )

        # Compare with baseline if requested
        if baseline_comparison:
            baseline_key = f"{plugin_id}:{benchmark_config.benchmark_type.value}"
            if baseline_key in self.benchmark_baselines:
                baseline = self.benchmark_baselines[baseline_key]
                benchmark_result.baseline_comparison = self._compare_benchmark_results(benchmark_result, baseline)

        # Check if meets criteria
        benchmark_result.meets_criteria = self._check_benchmark_criteria(benchmark_result, benchmark_config)

        # Store as new baseline if better than previous
        self._update_benchmark_baseline(plugin_id, benchmark_result)

        logger.info(f"Benchmark completed for {plugin_id}: {benchmark_config.benchmark_type.value}")
        return benchmark_result

    async def get_test_execution_status(self, execution_id: str) -> Optional[TestExecution]:
        """Get test execution status and results"""
        # Check active tests first
        if execution_id in self.active_tests:
            return self.active_tests[execution_id]

        # Query database
        return await TestExecution.find_one(TestExecution.execution_id == execution_id)

    async def generate_plugin_template(self, plugin_name: str, plugin_type: str, author: str, output_path: str) -> str:
        """Generate a plugin template with best practices"""

        template_dir = Path(output_path) / plugin_name
        template_dir.mkdir(parents=True, exist_ok=True)

        # Generate plugin.py
        plugin_code = self._generate_plugin_code_template(plugin_name, plugin_type, author)
        (template_dir / "plugin.py").write_text(plugin_code)

        # Generate manifest.json
        manifest = self._generate_manifest_template(plugin_name, plugin_type, author)
        (template_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))

        # Generate requirements.txt
        requirements = self._generate_requirements_template(plugin_type)
        (template_dir / "requirements.txt").write_text(requirements)

        # Generate test file
        test_code = self._generate_test_template(plugin_name, plugin_type)
        (template_dir / f"test_{plugin_name}.py").write_text(test_code)

        # Generate README.md
        readme = self._generate_readme_template(plugin_name, plugin_type, author)
        (template_dir / "README.md").write_text(readme)

        # Generate configuration file
        config = self._generate_config_template(plugin_name, plugin_type)
        (template_dir / "config.yml").write_text(yaml.dump(config, indent=2))

        logger.info(f"Generated plugin template: {template_dir}")
        return str(template_dir)

    async def _validate_package_structure(self, package_path: Path, validation_result: ValidationResult) -> None:
        """Validate plugin package structure"""

        required_files = ["plugin.py", "manifest.json"]
        recommended_files = ["README.md", "requirements.txt", "config.yml"]

        for required_file in required_files:
            if not (package_path / required_file).exists():
                validation_result.issues.append(
                    {
                        "severity": ValidationSeverity.CRITICAL,
                        "type": "missing_required_file",
                        "message": f"Required file missing: {required_file}",
                    }
                )
                validation_result.critical_count += 1
                validation_result.is_valid = False

        for recommended_file in recommended_files:
            if not (package_path / recommended_file).exists():
                validation_result.issues.append(
                    {
                        "severity": ValidationSeverity.WARNING,
                        "type": "missing_recommended_file",
                        "message": f"Recommended file missing: {recommended_file}",
                    }
                )
                validation_result.warning_count += 1

        # Check for common bad practices
        if (package_path / "__pycache__").exists():
            validation_result.issues.append(
                {
                    "severity": ValidationSeverity.WARNING,
                    "type": "build_artifacts",
                    "message": "Build artifacts (__pycache__) should not be included in package",
                }
            )
            validation_result.warning_count += 1

    async def _validate_plugin_manifest(self, package_path: Path, validation_result: ValidationResult) -> None:
        """Validate plugin manifest file"""

        manifest_path = package_path / "manifest.json"
        if not manifest_path.exists():
            return  # Already reported as critical error

        try:
            with open(manifest_path, "r") as f:
                manifest_data = json.load(f)

            # Validate required fields
            required_fields = [
                "name",
                "version",
                "description",
                "author",
                "entry_point",
            ]
            for field in required_fields:
                if field not in manifest_data:
                    validation_result.issues.append(
                        {
                            "severity": ValidationSeverity.ERROR,
                            "type": "missing_manifest_field",
                            "message": f"Required manifest field missing: {field}",
                        }
                    )
                    validation_result.error_count += 1

            # Validate version format
            if "version" in manifest_data:
                try:
                    # Simple version validation
                    version_parts = manifest_data["version"].split(".")
                    if len(version_parts) != 3 or not all(part.isdigit() for part in version_parts):
                        validation_result.issues.append(
                            {
                                "severity": ValidationSeverity.WARNING,
                                "type": "version_format",
                                "message": "Version should follow semantic versioning (e.g., 1.0.0)",
                            }
                        )
                        validation_result.warning_count += 1
                except Exception:
                    validation_result.issues.append(
                        {
                            "severity": ValidationSeverity.ERROR,
                            "type": "invalid_version",
                            "message": "Invalid version format",
                        }
                    )
                    validation_result.error_count += 1

        except json.JSONDecodeError as e:
            validation_result.issues.append(
                {
                    "severity": ValidationSeverity.CRITICAL,
                    "type": "invalid_manifest",
                    "message": f"Invalid JSON in manifest: {str(e)}",
                }
            )
            validation_result.critical_count += 1
            validation_result.is_valid = False

    async def _validate_code_quality(self, package_path: Path, validation_result: ValidationResult) -> None:
        """Validate Python code quality"""

        python_files = list(package_path.glob("*.py"))
        if not python_files:
            validation_result.issues.append(
                {
                    "severity": ValidationSeverity.ERROR,
                    "type": "no_python_files",
                    "message": "No Python files found in package",
                }
            )
            validation_result.error_count += 1
            return

        total_score = 0
        file_count = 0

        for py_file in python_files:
            try:
                with open(py_file, "r") as f:
                    code = f.read()

                # Parse AST to check syntax
                try:
                    tree = ast.parse(code)
                    file_count += 1

                    # Basic code quality checks
                    score = 100

                    # Check for docstrings
                    if not ast.get_docstring(tree):
                        validation_result.issues.append(
                            {
                                "severity": ValidationSeverity.WARNING,
                                "type": "missing_docstring",
                                "message": f"File {py_file.name} missing module docstring",
                            }
                        )
                        validation_result.warning_count += 1
                        score -= 10

                    # Check for proper imports
                    imports = [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
                    if not imports:
                        validation_result.issues.append(
                            {
                                "severity": ValidationSeverity.INFO,
                                "type": "no_imports",
                                "message": f"File {py_file.name} has no imports (might be simple)",
                            }
                        )
                        validation_result.info_count += 1

                    # Check for classes and functions
                    classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
                    functions = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]

                    if not classes and not functions:
                        validation_result.issues.append(
                            {
                                "severity": ValidationSeverity.WARNING,
                                "type": "empty_implementation",
                                "message": f"File {py_file.name} contains no classes or functions",
                            }
                        )
                        validation_result.warning_count += 1
                        score -= 20

                    total_score += score

                except SyntaxError as e:
                    validation_result.issues.append(
                        {
                            "severity": ValidationSeverity.CRITICAL,
                            "type": "syntax_error",
                            "message": f"Syntax error in {py_file.name}: {str(e)}",
                        }
                    )
                    validation_result.critical_count += 1
                    validation_result.is_valid = False

            except Exception as e:
                validation_result.issues.append(
                    {
                        "severity": ValidationSeverity.ERROR,
                        "type": "file_read_error",
                        "message": f"Error reading {py_file.name}: {str(e)}",
                    }
                )
                validation_result.error_count += 1

        # Calculate code quality score
        if file_count > 0:
            validation_result.code_quality_score = total_score / file_count
        else:
            validation_result.code_quality_score = 0

    async def _validate_security(self, package_path: Path, validation_result: ValidationResult) -> None:
        """Basic security validation"""

        python_files = list(package_path.glob("*.py"))
        security_score = 100

        for py_file in python_files:
            try:
                with open(py_file, "r") as f:
                    code = f.read()

                # Check for potential security issues
                security_issues = [
                    ("eval(", "Use of eval() function"),
                    ("exec(", "Use of exec() function"),
                    ("subprocess.call", "Direct subprocess call"),
                    ("os.system", "Use of os.system()"),
                    ("import pickle", "Use of pickle module"),
                    ("__import__", "Dynamic import"),
                ]

                for pattern, description in security_issues:
                    if pattern in code:
                        validation_result.issues.append(
                            {
                                "severity": ValidationSeverity.WARNING,
                                "type": "security_concern",
                                "message": f"Security concern in {py_file.name}: {description}",
                            }
                        )
                        validation_result.warning_count += 1
                        security_score -= 15

                # Check for hardcoded secrets (basic patterns)
                secret_patterns = [
                    (r"password\s*=\s*['\"][^'\"]+['\"]", "Hardcoded password"),
                    (r"api_key\s*=\s*['\"][^'\"]+['\"]", "Hardcoded API key"),
                    (r"secret\s*=\s*['\"][^'\"]+['\"]", "Hardcoded secret"),
                ]

                import re

                for pattern, description in secret_patterns:
                    if re.search(pattern, code, re.IGNORECASE):
                        validation_result.issues.append(
                            {
                                "severity": ValidationSeverity.ERROR,
                                "type": "hardcoded_secret",
                                "message": f"Potential hardcoded secret in {py_file.name}: {description}",
                            }
                        )
                        validation_result.error_count += 1
                        security_score -= 25

            except Exception:
                continue

        validation_result.security_score = max(0, security_score)

    async def _validate_performance_indicators(self, package_path: Path, validation_result: ValidationResult) -> None:
        """Validate performance indicators"""

        # This is a basic implementation - in production would be more sophisticated
        validation_result.performance_score = 75.0  # Default score

        # Check for async/await usage (good for performance)
        python_files = list(package_path.glob("*.py"))
        has_async = False

        for py_file in python_files:
            try:
                with open(py_file, "r") as f:
                    code = f.read()

                if "async def" in code or "await " in code:
                    has_async = True
                    validation_result.performance_score += 10
                    break

            except Exception:
                continue

        if has_async:
            validation_result.recommendations.append("Good: Plugin uses async/await for better performance")
        else:
            validation_result.recommendations.append(
                "Consider using async/await for better performance in I/O operations"
            )

    def _calculate_validation_scores(self, validation_result: ValidationResult) -> None:
        """Calculate final validation scores"""

        # Start with base score
        score = 100.0

        # Deduct points for issues
        score -= validation_result.critical_count * 25
        score -= validation_result.error_count * 10
        score -= validation_result.warning_count * 5
        score -= validation_result.info_count * 1

        # Ensure minimum score
        validation_result.validation_score = max(0.0, score)

        # Overall validity
        if validation_result.critical_count > 0:
            validation_result.is_valid = False

        # Generate recommendations based on scores
        if validation_result.code_quality_score < 60:
            validation_result.recommendations.append("Improve code quality by adding docstrings and proper structure")

        if validation_result.security_score < 80:
            validation_result.recommendations.append("Address security concerns identified in the code")

        if validation_result.performance_score < 70:
            validation_result.recommendations.append("Consider performance optimizations for better execution")

    async def _execute_test_suite_async(self, test_suite: TestSuite, execution: TestExecution) -> None:
        """Execute test suite asynchronously"""
        try:
            execution.overall_status = TestStatus.RUNNING
            execution.started_at = datetime.utcnow()
            await execution.save()

            # Execute test cases
            for test_case in test_suite.test_cases:
                if execution.overall_status == TestStatus.ERROR:
                    break

                test_result = await self._execute_test_case(test_case, execution)
                execution.test_results.append(test_result)

                # Update counters
                if test_result.status == TestStatus.PASSED:
                    execution.passed_tests += 1
                elif test_result.status == TestStatus.FAILED:
                    execution.failed_tests += 1
                elif test_result.status == TestStatus.SKIPPED:
                    execution.skipped_tests += 1
                elif test_result.status == TestStatus.ERROR:
                    execution.error_tests += 1
                    if not test_suite.continue_on_failure:
                        execution.overall_status = TestStatus.ERROR
                        break

            # Calculate final results
            execution.success_rate = (
                execution.passed_tests / execution.total_tests if execution.total_tests > 0 else 0.0
            )

            # Determine overall status
            if execution.overall_status != TestStatus.ERROR:
                if execution.success_rate >= test_suite.minimum_success_rate / 100:
                    execution.overall_status = TestStatus.PASSED
                else:
                    execution.overall_status = TestStatus.FAILED

        except Exception as e:
            logger.error(f"Test suite execution failed: {e}")
            execution.overall_status = TestStatus.ERROR

        finally:
            execution.completed_at = datetime.utcnow()
            if execution.started_at:
                execution.duration_seconds = (execution.completed_at - execution.started_at).total_seconds()

            await execution.save()

            # Remove from active tests
            self.active_tests.pop(execution.execution_id, None)

            logger.info(f"Test suite execution completed: {execution.execution_id} - {execution.overall_status.value}")

    async def _execute_test_case(self, test_case: TestCase, execution: TestExecution) -> TestResult:
        """Execute a single test case"""
        started_at = datetime.utcnow()

        test_result = TestResult(
            test_id=test_case.test_id,
            test_name=test_case.name,
            status=TestStatus.RUNNING,
            started_at=started_at,
        )

        try:
            # This would execute the actual test commands
            # For now, simulate test execution
            await asyncio.sleep(1)  # Simulate test time

            # Mock test result based on test name
            if "fail" in test_case.name.lower():
                test_result.status = TestStatus.FAILED
                test_result.error_message = "Simulated test failure"
            else:
                test_result.status = TestStatus.PASSED
                test_result.assertions_passed = 5

            test_result.return_code = 0 if test_result.status == TestStatus.PASSED else 1

        except Exception as e:
            test_result.status = TestStatus.ERROR
            test_result.error_message = str(e)
            test_result.stack_trace = traceback.format_exc()

        finally:
            test_result.completed_at = datetime.utcnow()
            test_result.duration_seconds = (test_result.completed_at - test_result.started_at).total_seconds()

        return test_result

    async def _generate_default_test_cases(self, plugin_id: str) -> List[TestCase]:
        """Generate default test cases for a plugin"""

        test_cases = [
            TestCase(
                name="Plugin Initialization Test",
                description="Test plugin initialization and basic functionality",
                test_type=TestEnvironmentType.UNIT,
                test_commands=["python -c 'import plugin; plugin.test_init()'"],
            ),
            TestCase(
                name="Plugin Configuration Test",
                description="Test plugin configuration loading and validation",
                test_type=TestEnvironmentType.UNIT,
                test_commands=["python -c 'import plugin; plugin.test_config()'"],
            ),
            TestCase(
                name="Plugin Integration Test",
                description="Test plugin integration with OpenWatch system",
                test_type=TestEnvironmentType.INTEGRATION,
                test_commands=["python -c 'import plugin; plugin.test_integration()'"],
            ),
            TestCase(
                name="Plugin Performance Test",
                description="Test plugin performance under normal load",
                test_type=TestEnvironmentType.PERFORMANCE,
                test_commands=["python -c 'import plugin; plugin.test_performance()'"],
                timeout_seconds=600,
            ),
        ]

        return test_cases

    async def _benchmark_throughput(self, plugin: InstalledPlugin, config: BenchmarkConfig) -> Dict[str, Any]:
        """Benchmark plugin throughput"""
        # Mock implementation
        return {
            "throughput_ops_per_sec": 150.0 + (hash(plugin.plugin_id) % 50),
            "success_rate": 0.98,
            "error_count": 2,
        }

    async def _benchmark_latency(self, plugin: InstalledPlugin, config: BenchmarkConfig) -> Dict[str, Any]:
        """Benchmark plugin latency"""
        # Mock implementation
        base_latency = 50.0 + (hash(plugin.plugin_id) % 100)
        return {
            "avg_latency_ms": base_latency,
            "p95_latency_ms": base_latency * 1.5,
            "p99_latency_ms": base_latency * 2.0,
            "success_rate": 0.99,
            "error_count": 1,
        }

    async def _benchmark_memory(self, plugin: InstalledPlugin, config: BenchmarkConfig) -> Dict[str, Any]:
        """Benchmark plugin memory usage"""
        # Mock implementation
        base_memory = 100.0 + (hash(plugin.plugin_id) % 200)
        return {
            "avg_memory_mb": base_memory,
            "peak_memory_mb": base_memory * 1.3,
            "success_rate": 1.0,
            "error_count": 0,
        }

    async def _benchmark_cpu(self, plugin: InstalledPlugin, config: BenchmarkConfig) -> Dict[str, Any]:
        """Benchmark plugin CPU usage"""
        # Mock implementation
        base_cpu = 20.0 + (hash(plugin.plugin_id) % 30)
        return {
            "avg_cpu_percent": base_cpu,
            "peak_cpu_percent": base_cpu * 1.4,
            "success_rate": 0.99,
            "error_count": 1,
        }

    async def _benchmark_scalability(self, plugin: InstalledPlugin, config: BenchmarkConfig) -> Dict[str, Any]:
        """Benchmark plugin scalability"""
        # Mock implementation
        return {
            "throughput_ops_per_sec": 200.0,
            "avg_latency_ms": 80.0,
            "success_rate": 0.97,
            "error_count": 5,
        }

    def _compare_benchmark_results(self, current: BenchmarkResult, baseline: BenchmarkResult) -> Dict[str, float]:
        """Compare benchmark results with baseline"""
        comparison = {}

        if current.throughput_ops_per_sec and baseline.throughput_ops_per_sec:
            comparison["throughput_improvement"] = (
                current.throughput_ops_per_sec - baseline.throughput_ops_per_sec
            ) / baseline.throughput_ops_per_sec

        if current.avg_latency_ms and baseline.avg_latency_ms:
            comparison["latency_improvement"] = (
                baseline.avg_latency_ms - current.avg_latency_ms
            ) / baseline.avg_latency_ms

        if current.avg_memory_mb and baseline.avg_memory_mb:
            comparison["memory_improvement"] = (baseline.avg_memory_mb - current.avg_memory_mb) / baseline.avg_memory_mb

        return comparison

    def _check_benchmark_criteria(self, result: BenchmarkResult, config: BenchmarkConfig) -> bool:
        """Check if benchmark meets configured criteria"""
        meets_criteria = True

        if config.min_throughput and result.throughput_ops_per_sec:
            meets_criteria &= result.throughput_ops_per_sec >= config.min_throughput

        if config.max_latency_ms and result.avg_latency_ms:
            meets_criteria &= result.avg_latency_ms <= config.max_latency_ms

        if config.max_memory_mb and result.avg_memory_mb:
            meets_criteria &= result.avg_memory_mb <= config.max_memory_mb

        return meets_criteria

    def _update_benchmark_baseline(self, plugin_id: str, result: BenchmarkResult) -> None:
        """Update benchmark baseline if result is better"""
        baseline_key = f"{plugin_id}:{result.benchmark_type.value}"

        if baseline_key not in self.benchmark_baselines:
            self.benchmark_baselines[baseline_key] = result
        else:
            current_baseline = self.benchmark_baselines[baseline_key]

            # Simple comparison - could be more sophisticated
            if (result.throughput_ops_per_sec or 0) > (current_baseline.throughput_ops_per_sec or 0):
                self.benchmark_baselines[baseline_key] = result

    def _generate_plugin_code_template(self, plugin_name: str, plugin_type: str, author: str) -> str:
        """Generate plugin code template"""
        return f'''"""
{plugin_name} Plugin for OpenWatch
Author: {author}
"""
import logging
from typing import Dict, Any, Optional
from datetime import datetime

from openwatch.plugins.base import PluginInterface
from openwatch.plugins.types import PluginType, ExecutionResult


logger = logging.getLogger(__name__)


class {plugin_name.title().replace('_', '')}Plugin(PluginInterface):
    """
    {plugin_name} plugin implementation

    This plugin provides {plugin_type} functionality for OpenWatch.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.name = "{plugin_name}"
        self.version = "1.0.0"
        self.plugin_type = PluginType.{plugin_type.upper()}

    async def initialize(self) -> bool:
        """Initialize the plugin"""
        try:
            logger.info(f"Initializing {{self.name}} plugin")

            # Plugin initialization logic here

            logger.info(f"{{self.name}} plugin initialized successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize {{self.name}} plugin: {{e}}")
            return False

    async def execute(self, context: Dict[str, Any]) -> ExecutionResult:
        """Execute plugin functionality"""
        try:
            logger.info(f"Executing {{self.name}} plugin")

            # Plugin execution logic here

            return ExecutionResult(
                success=True,
                message="Plugin executed successfully",
                data={{"timestamp": datetime.utcnow().isoformat()}}
            )

        except Exception as e:
            logger.error(f"Plugin execution failed: {{e}}")
            return ExecutionResult(
                success=False,
                message=f"Execution failed: {{str(e)}}",
                error=str(e)
            )

    async def cleanup(self) -> bool:
        """Cleanup plugin resources"""
        try:
            logger.info(f"Cleaning up {{self.name}} plugin")

            # Plugin cleanup logic here

            return True

        except Exception as e:
            logger.error(f"Plugin cleanup failed: {{e}}")
            return False

    def get_health_status(self) -> Dict[str, Any]:
        """Get plugin health status"""
        return {{
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": self.version
        }}


# Plugin entry point
plugin_class = {plugin_name.title().replace('_', '')}Plugin
'''

    def _generate_manifest_template(self, plugin_name: str, plugin_type: str, author: str) -> Dict[str, Any]:
        """Generate manifest template"""
        return {
            "name": plugin_name,
            "version": "1.0.0",
            "description": f"OpenWatch {plugin_type} plugin",
            "author": author,
            "license": "MIT",
            "plugin_type": plugin_type,
            "entry_point": "plugin.py",
            "supported_platforms": ["linux", "windows", "macos"],
            "dependencies": ["requests>=2.25.0", "pydantic>=1.8.0"],
            "openwatch_version": ">=1.0.0",
            "capabilities": [f"{plugin_type}_execution", "health_monitoring"],
            "configuration_schema": {
                "type": "object",
                "properties": {
                    "enabled": {"type": "boolean", "default": True},
                    "timeout": {"type": "integer", "default": 300},
                },
            },
        }

    def _generate_requirements_template(self, plugin_type: str) -> str:
        """Generate requirements template"""
        base_requirements = ["requests>=2.25.0", "pydantic>=1.8.0", "pyyaml>=5.4.0"]

        if plugin_type == "scanner":
            base_requirements.extend(["lxml>=4.6.0", "paramiko>=2.7.0"])
        elif plugin_type == "remediation":
            base_requirements.extend(["ansible>=4.0.0", "paramiko>=2.7.0"])

        return "\n".join(base_requirements)

    def _generate_test_template(self, plugin_name: str, plugin_type: str) -> str:
        """Generate test template"""
        class_name = plugin_name.title().replace("_", "")
        return f'''"""
Tests for {plugin_name} plugin
"""
import pytest
import asyncio
from unittest.mock import Mock, patch

from plugin import {class_name}Plugin


class Test{class_name}Plugin:
    """Test cases for {plugin_name} plugin"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance for testing"""
        return {class_name}Plugin({{"test_mode": True}})

    @pytest.mark.asyncio
    async def test_plugin_initialization(self, plugin):
        """Test plugin initialization"""
        result = await plugin.initialize()
        assert result is True
        assert plugin.name == "{plugin_name}"

    @pytest.mark.asyncio
    async def test_plugin_execution(self, plugin):
        """Test plugin execution"""
        await plugin.initialize()

        context = {{"test_data": "test_value"}}
        result = await plugin.execute(context)

        assert result.success is True
        assert result.message is not None

    @pytest.mark.asyncio
    async def test_plugin_cleanup(self, plugin):
        """Test plugin cleanup"""
        await plugin.initialize()
        result = await plugin.cleanup()
        assert result is True

    def test_plugin_health_status(self, plugin):
        """Test plugin health status"""
        health = plugin.get_health_status()
        assert "status" in health
        assert "timestamp" in health
        assert "version" in health

    @pytest.mark.asyncio
    async def test_plugin_error_handling(self, plugin):
        """Test plugin error handling"""
        with patch.object(plugin, '_internal_method', side_effect=Exception("Test error")):
            result = await plugin.execute({{}})
            assert result.success is False
            assert "error" in result.error
'''

    def _generate_readme_template(self, plugin_name: str, plugin_type: str, author: str) -> str:
        """Generate README template"""
        return f"""# {plugin_name.title()} Plugin

OpenWatch {plugin_type} plugin by {author}.

## Description

This plugin provides {plugin_type} functionality for the OpenWatch security scanning platform.

## Installation

1. Download the plugin package
2. Install using OpenWatch plugin manager:
   ```bash
   openwatch plugin install {plugin_name}-1.0.0.zip
   ```

## Configuration

The plugin supports the following configuration options:

- `enabled`: Enable/disable the plugin (default: true)
- `timeout`: Execution timeout in seconds (default: 300)

## Usage

The plugin is automatically invoked by OpenWatch when {plugin_type} operations are needed.

## Development

### Running Tests

```bash
pytest test_{plugin_name}.py
```

### Building Package

```bash
zip -r {plugin_name}-1.0.0.zip plugin.py manifest.json requirements.txt config.yml README.md
```

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions, please contact {author}.
"""

    def _generate_config_template(self, plugin_name: str, plugin_type: str) -> Dict[str, Any]:
        """Generate configuration template"""
        return {
            "plugin": {"name": plugin_name, "enabled": True, "log_level": "INFO"},
            "execution": {"timeout": 300, "retries": 3, "parallel": False},
            "monitoring": {"health_check_interval": 60, "metrics_enabled": True},
        }
