"""
Engine Module - Unified API for Scan Execution Operations

This module provides a comprehensive, unified API for all compliance scan
execution operations in OpenWatch. It consolidates executors, scanners,
integrations, and result handling into a single, well-documented interface.

Architecture Overview:
    The engine module follows a layered architecture:

    1. Executors Layer (engine.executors)
       - Handles transport and execution of scans
       - SSH executor for remote hosts
       - Local executor for container/self-assessment
       - Manages connection, file transfer, command execution

    2. Scanners Layer (engine.scanners)
       - Handles content operations
       - Content validation and profile extraction
       - Command building and result parsing
       - Scanner capability metadata

    3. Integration Layer (engine.integration)
       - AEGIS remediation system mapping
       - Semantic SCAP analysis engine
       - Cross-framework compliance intelligence

    4. Providers Layer (engine.providers) - Future
       - AWS Security Hub integration
       - Azure Security Center integration
       - GCP Security Command Center integration

    5. Models Layer (engine.models)
       - Defines shared data structures
       - Execution context and results
       - Scanner capabilities and status

Design Philosophy:
    - Single Responsibility: Each component handles one aspect
    - Immutable Data: Results and context are frozen dataclasses
    - Type Safety: Full type annotations for IDE support
    - Security-First: Credential isolation, input validation
    - Defensive Coding: Graceful error handling

Supported Execution Modes:
    - SSH: Remote execution via Paramiko SSH connections
    - LOCAL: Direct execution on the same host
    - AGENT: Future agent-based execution (planned)

Quick Start:
    # Execute a remote scan
    from backend.app.services.engine import (
        SSHExecutor,
        ExecutionContext,
        ScanType,
    )

    context = ExecutionContext(
        scan_id="scan-123",
        scan_type=ScanType.XCCDF_PROFILE,
        hostname="192.168.1.100",
        timeout=1800,
    )

    executor = SSHExecutor(db=session)
    result = executor.execute(
        context=context,
        content_path=Path("/app/data/scap/xccdf.xml"),
        profile_id="xccdf_org.ssgproject.content_profile_stig",
        credential_data=credentials,
    )

    if result.success:
        print(f"Scan completed with exit code {result.exit_code}")
        print(f"Results at: {result.result_files}")

    # Use AEGIS integration for remediation
    from backend.app.services.engine import AegisMapper, get_aegis_mapper

    mapper = get_aegis_mapper()
    plan = mapper.create_remediation_plan(
        scan_id="scan-123",
        host_id="host-456",
        failed_rules=result.failed_rules,
        platform="rhel9"
    )

    # Use Semantic Engine for intelligent analysis
    from backend.app.services.engine import SemanticEngine, get_semantic_engine

    engine = get_semantic_engine()
    analysis = await engine.process_scan_with_intelligence(
        scan_results=result.to_dict(),
        scan_id="scan-123",
        host_info={"host_id": "host-456", "os_version": "RHEL 9"}
    )

Module Structure:
    engine/
    ├── __init__.py           # This file - public API
    ├── models.py             # Shared data models
    ├── exceptions.py         # Engine-specific exceptions
    ├── executors/            # Execution backends
    │   ├── __init__.py       # Executor registry
    │   ├── base.py           # Abstract base executor
    │   ├── ssh.py            # SSH remote executor
    │   └── local.py          # Local executor
    ├── scanners/             # Content operations
    │   ├── __init__.py       # Scanner registry
    │   ├── base.py           # Abstract base scanner
    │   ├── oscap.py          # OpenSCAP scanner
    │   ├── scap.py           # Unified SCAP scanner (MongoDB-integrated)
    │   └── kubernetes.py     # Kubernetes/OpenShift scanner
    ├── orchestration/        # Scan coordination
    │   ├── __init__.py       # Orchestration exports
    │   └── orchestrator.py   # Multi-scanner coordinator
    ├── integration/          # External system integrations
    │   ├── __init__.py       # Integration exports
    │   ├── aegis_mapper.py   # AEGIS remediation mapping
    │   └── semantic_engine.py # Semantic SCAP analysis
    ├── providers/            # Cloud provider integrations (future)
    │   ├── __init__.py       # Provider exports
    │   └── base.py           # Abstract base provider
    └── result_parsers/       # Result file parsing
        ├── __init__.py       # Parser registry
        ├── base.py           # Abstract base parser
        ├── xccdf.py          # XCCDF result parser
        └── arf.py            # ARF result parser

Related Modules:
    - services.content: Content parsing and transformation
    - services.ssh: SSH connection management
    - tasks.scan_tasks: Celery scan task orchestration

Dependency Resolution:
    The engine module includes dependency resolution for SCAP content,
    ensuring all referenced files (OVAL, CPE, tailoring) are identified
    before remote transfer. See dependency_resolver.py for details.

Security Notes:
    - Credentials never stored, only passed transiently
    - SSH connections use SSHConnectionManager policies
    - Content validation prevents XXE attacks
    - Error messages sanitized to prevent info disclosure
    - AEGIS commands stored but not executed by this module

Performance Notes:
    - Executors are stateless (create per-scan)
    - Scanners can be reused across scans
    - File transfers verified with size checks
    - Timeouts prevent hung scans
    - Semantic engine uses caching for rule mappings
"""

import logging
from typing import Optional

from sqlalchemy.orm import Session

# Re-export dependency resolver
from .dependency_resolver import SCAPDependency, SCAPDependencyResolver, get_dependency_resolver

# Re-export discovery layer (JIT platform detection for scans)
from .discovery import PlatformDetector, PlatformInfo, detect_platform_for_scan

# Re-export exceptions for error handling
from .exceptions import (  # Base exceptions; Executor exceptions; Scanner exceptions; Other exceptions; Backward compatibility
    ContentValidationError,
    DependencyError,
    EngineError,
    ExecutorError,
    FileTransferError,
    LocalExecutionError,
    RemoteSCAPExecutionError,
    ResourceExhaustedError,
    ResultParseError,
    ScanExecutionError,
    ScannerError,
    ScanTimeoutError,
    SCAPBaseError,
    SSHExecutionError,
)

# Re-export executors
from .executors import BaseExecutor, LocalExecutor, SSHExecutor, get_executor

# Re-export integrations
from .integration import (  # AEGIS Mapper; Semantic Engine
    AegisMapper,
    AEGISMapping,
    IntelligentScanResult,
    RemediationPlan,
    SemanticEngine,
    SemanticRule,
    get_aegis_mapper,
    get_semantic_engine,
)

# Re-export models for convenient access
from .models import (  # Enums; Execution context; Result types; Capabilities; File transfer
    ExecutionContext,
    ExecutionMode,
    FileTransferSpec,
    LocalScanResult,
    RemoteScanResult,
    ScannerCapabilities,
    ScanProvider,
    ScanResult,
    ScanStatus,
    ScanType,
)

# Re-export orchestration layer
from .orchestration import ScanOrchestrator

# Re-export providers (base classes for future implementations)
from .providers import BaseProvider, ProviderCapability, ProviderConfig, ProviderError

# Re-export result parsers
from .result_parsers import (
    ARFResultParser,
    BaseResultParser,
    ParsedResults,
    ResultStatistics,
    RuleResult,
    XCCDFResultParser,
    get_parser,
    get_parser_for_file,
)

# Re-export scanners
from .scanners import (
    BaseScanner,
    KubernetesScanner,
    OSCAPScanner,
    ScannerFactory,
    UnifiedSCAPScanner,
    get_scanner,
    get_scanner_for_content,
    get_unified_scanner,
)

logger = logging.getLogger(__name__)

# Version of the engine module API
# 1.5.0 - Added discovery layer (PlatformDetector for JIT platform detection)
# 1.4.0 - Added orchestration layer (ScanOrchestrator)
# 1.3.0 - Added SCAPDependencyResolver for SCAP content dependency analysis
# 1.2.0 - Added integration layer (AegisMapper, SemanticEngine) and providers layer
__version__ = "1.5.0"


# =============================================================================
# Factory Functions
# =============================================================================


def create_executor(
    mode: ExecutionMode,
    db: Optional[Session] = None,
) -> BaseExecutor:
    """
    Create an executor for the specified execution mode.

    This is the recommended way to obtain executor instances,
    as it handles dependency injection automatically.

    Args:
        mode: Execution mode (SSH, LOCAL, AGENT).
        db: Database session (required for SSH mode).

    Returns:
        Configured executor instance.

    Raises:
        ValueError: If mode is unsupported or dependencies missing.

    Example:
        >>> executor = create_executor(ExecutionMode.SSH, db=session)
        >>> result = executor.execute(context, content_path, profile_id, creds)
    """
    return get_executor(mode, db)


def create_scanner(provider: ScanProvider) -> BaseScanner:
    """
    Create a scanner for the specified provider.

    Args:
        provider: Scanner provider (OSCAP, KUBERNETES, CUSTOM).

    Returns:
        Configured scanner instance.

    Raises:
        ValueError: If provider is unsupported.

    Example:
        >>> scanner = create_scanner(ScanProvider.OSCAP)
        >>> profiles = scanner.extract_profiles(content_path)
    """
    return get_scanner(provider)


def create_execution_context(
    scan_id: str,
    scan_type: ScanType,
    hostname: str,
    port: int = 22,
    timeout: int = 1800,
    **kwargs,
) -> ExecutionContext:
    """
    Create an execution context for scan operations.

    Convenience function to build ExecutionContext with common defaults.

    Args:
        scan_id: Unique scan identifier.
        scan_type: Type of scan to execute.
        hostname: Target host for scanning.
        port: SSH port (default 22).
        timeout: Execution timeout in seconds.
        **kwargs: Additional context parameters.

    Returns:
        Configured ExecutionContext instance.

    Example:
        >>> context = create_execution_context(
        ...     scan_id="scan-123",
        ...     scan_type=ScanType.XCCDF_PROFILE,
        ...     hostname="192.168.1.100",
        ... )
    """
    return ExecutionContext(
        scan_id=scan_id,
        scan_type=scan_type,
        hostname=hostname,
        port=port,
        timeout=timeout,
        **kwargs,
    )


# =============================================================================
# Backward Compatibility Aliases
# =============================================================================

# These aliases maintain compatibility with code importing from
# remote_scap_executor.py. New code should use canonical names.

RemoteSCAPExecutor = SSHExecutor


# =============================================================================
# Public API
# =============================================================================

__all__ = [
    # Version
    "__version__",
    # Enums
    "ExecutionMode",
    "ScanProvider",
    "ScanStatus",
    "ScanType",
    # Models
    "ExecutionContext",
    "FileTransferSpec",
    "LocalScanResult",
    "RemoteScanResult",
    "ScannerCapabilities",
    "ScanResult",
    # Exceptions
    "ContentValidationError",
    "DependencyError",
    "EngineError",
    "ExecutorError",
    "FileTransferError",
    "LocalExecutionError",
    "RemoteSCAPExecutionError",
    "ResourceExhaustedError",
    "ResultParseError",
    "ScanExecutionError",
    "ScannerError",
    "ScanTimeoutError",
    "SCAPBaseError",
    "SSHExecutionError",
    # Executors
    "BaseExecutor",
    "LocalExecutor",
    "SSHExecutor",
    "get_executor",
    # Scanners
    "BaseScanner",
    "OSCAPScanner",
    "UnifiedSCAPScanner",
    "KubernetesScanner",
    "ScannerFactory",
    "get_scanner",
    "get_scanner_for_content",
    "get_unified_scanner",
    # Result Parsers
    "BaseResultParser",
    "ParsedResults",
    "ResultStatistics",
    "RuleResult",
    "XCCDFResultParser",
    "ARFResultParser",
    "get_parser_for_file",
    "get_parser",
    # Integration Layer - AEGIS Mapper
    "AegisMapper",
    "AEGISMapping",
    "RemediationPlan",
    "get_aegis_mapper",
    # Integration Layer - Semantic Engine
    "SemanticEngine",
    "SemanticRule",
    "IntelligentScanResult",
    "get_semantic_engine",
    # Providers Layer
    "BaseProvider",
    "ProviderCapability",
    "ProviderConfig",
    "ProviderError",
    # Factory functions
    "create_executor",
    "create_scanner",
    "create_execution_context",
    # Dependency Resolution
    "SCAPDependency",
    "SCAPDependencyResolver",
    "get_dependency_resolver",
    # Orchestration Layer
    "ScanOrchestrator",
    # Discovery Layer (JIT platform detection)
    "PlatformDetector",
    "PlatformInfo",
    "detect_platform_for_scan",
    # Backward compatibility
    "RemoteSCAPExecutor",
]

# Module initialization logging
logger.debug("Engine module initialized (v%s)", __version__)
