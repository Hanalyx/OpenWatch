"""
Engine Module Shared Models and Types

This module defines the core data structures used across the scan execution engine,
including scan types, scan results, execution context, and provider configurations.

These models are used by:
- Scan executors (SSH, local, container-based)
- Scanner implementations (OSCAP, Kubernetes, custom)
- Scan orchestrators and schedulers
- Result processors and reporters

Design Principles:
- Immutable where possible (frozen dataclasses for thread-safety)
- Type-safe with explicit type hints (MyPy strict mode compatible)
- Framework-agnostic (no database dependencies in models)
- Serializable to JSON for API responses and task queues
- Security-conscious (no credential storage in models)

Security Notes:
- Models never store plaintext credentials
- Sensitive data fields are marked for redaction in logging
- Execution context isolates security-relevant parameters
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class ScanType(str, Enum):
    """
    Supported SCAP scan types for compliance evaluation.

    Each scan type represents a different mode of compliance scanning
    supported by the OpenWatch engine. The type determines which
    executor and oscap command variant will be used.

    Attributes:
        XCCDF_PROFILE: Standard XCCDF profile scan (most common)
        XCCDF_RULE: Single rule scan for targeted evaluation
        OVAL_DEFINITIONS: OVAL-only scan for vulnerability detection
        DATASTREAM: SCAP 1.3 datastream scan (bundled content)
        MONGODB_GENERATED: MongoDB-generated content from rule builder
        OWSCAN_CUSTOM: Future OWScan custom scan format

    Usage:
        >>> scan_type = ScanType.XCCDF_PROFILE
        >>> if scan_type == ScanType.DATASTREAM:
        ...     use_datastream_mode = True
    """

    XCCDF_PROFILE = "xccdf_profile"
    XCCDF_RULE = "xccdf_rule"
    OVAL_DEFINITIONS = "oval_definitions"
    DATASTREAM = "datastream"
    MONGODB_GENERATED = "mongodb_generated"
    OWSCAN_CUSTOM = "owscan_custom"


class ScanProvider(str, Enum):
    """
    Scan execution providers/engines available in OpenWatch.

    Each provider represents a different scanning technology or tool
    that can be used to evaluate compliance. The provider determines
    which scanner implementation is instantiated.

    Attributes:
        OSCAP: OpenSCAP scanner (primary provider for SCAP content)
        KUBERNETES: Kubernetes-native compliance scanner
        CUSTOM: Custom scanner plugins (future extension point)

    Usage:
        >>> provider = ScanProvider.OSCAP
        >>> scanner = get_scanner_for_provider(provider)
    """

    OSCAP = "oscap"
    KUBERNETES = "kubernetes"
    CUSTOM = "custom"


class ExecutionMode(str, Enum):
    """
    Scan execution modes determining where and how scans run.

    The execution mode determines the transport mechanism and
    execution environment for compliance scans.

    Attributes:
        LOCAL: Execute scan on the local host (container/server)
        SSH: Execute scan on remote host via SSH connection
        AGENT: Execute via OpenWatch agent (future capability)

    Usage:
        >>> mode = ExecutionMode.SSH
        >>> executor = get_executor_for_mode(mode)
    """

    LOCAL = "local"
    SSH = "ssh"
    AGENT = "agent"


class ScanStatus(str, Enum):
    """
    Scan execution status values.

    Tracks the lifecycle state of a scan from creation through
    completion or failure.

    Attributes:
        PENDING: Scan created but not yet started
        QUEUED: Scan queued for execution
        RUNNING: Scan currently executing
        COMPLETED: Scan finished successfully
        FAILED: Scan terminated with error
        CANCELLED: Scan cancelled by user or system
        TIMEOUT: Scan exceeded maximum execution time
    """

    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


@dataclass(frozen=True)
class ExecutionContext:
    """
    Immutable execution context for scan operations.

    Encapsulates all parameters needed to execute a scan, providing
    a clean interface for executors. This context is passed through
    the execution pipeline and should contain no mutable state.

    Attributes:
        scan_id: Unique identifier for this scan execution
        scan_type: Type of SCAP scan to perform
        hostname: Target hostname or IP address
        port: SSH port number (default 22)
        username: Username for authentication (not the credential itself)
        timeout: Maximum execution time in seconds
        working_dir: Local working directory for scan files
        remote_dir: Remote working directory (SSH mode only)
        environment: Additional environment variables for scan

    Security Notes:
        - Does NOT contain credentials (passed separately)
        - Username is for context only, not authentication
        - Environment dict should not contain secrets
    """

    scan_id: str
    scan_type: ScanType
    hostname: str
    port: int = 22
    username: str = ""
    timeout: int = 1800
    working_dir: Path = field(default_factory=lambda: Path("/app/data/results"))
    remote_dir: str = ""
    environment: Dict[str, str] = field(default_factory=dict)


@dataclass
class ScanResult:
    """
    Base result from scan execution.

    Contains the core outcome data from any scan execution,
    regardless of provider or execution mode. Extended by
    provider-specific result classes.

    Attributes:
        success: Whether scan completed without errors
        scan_id: Unique scan identifier
        status: Current scan status
        exit_code: Process exit code (0=pass, 2=fail with findings)
        stdout: Standard output from scan process
        stderr: Standard error output from scan process
        start_time: When scan execution began
        end_time: When scan execution completed
        execution_time_seconds: Total execution duration
        error_message: Error description if scan failed

    Usage:
        >>> result = ScanResult(
        ...     success=True,
        ...     scan_id="scan-123",
        ...     status=ScanStatus.COMPLETED,
        ...     exit_code=2,  # Some rules failed
        ...     execution_time_seconds=45.3
        ... )
        >>> if result.success:
        ...     process_findings(result)
    """

    success: bool
    scan_id: str
    status: ScanStatus
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    execution_time_seconds: float = 0.0
    error_message: Optional[str] = None

    @property
    def has_findings(self) -> bool:
        """
        Check if scan produced compliance findings.

        In OSCAP, exit code 2 indicates some rules failed (findings exist).
        Exit code 0 means all rules passed (no findings).

        Returns:
            True if scan has compliance findings to process.
        """
        # Exit code 2 means some rules failed = findings exist
        return self.exit_code == 2

    @property
    def all_passed(self) -> bool:
        """
        Check if all rules passed.

        Returns:
            True if scan completed and all rules passed.
        """
        return self.success and self.exit_code == 0

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert result to dictionary for JSON serialization.

        Returns:
            Dictionary representation safe for JSON encoding.
        """
        return {
            "success": self.success,
            "scan_id": self.scan_id,
            "status": self.status.value,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "execution_time_seconds": self.execution_time_seconds,
            "error_message": self.error_message,
            "has_findings": self.has_findings,
            "all_passed": self.all_passed,
        }


@dataclass
class RemoteScanResult(ScanResult):
    """
    Result from remote SCAP scan execution via SSH.

    Extends ScanResult with additional data specific to remote
    execution including file transfer details and result file paths.

    Attributes:
        hostname: Remote host where scan was executed
        result_files: Mapping of result type to local file path
        files_transferred: Number of files transferred to remote
        remote_dir: Remote directory used for scan (for debugging)

    Usage:
        >>> result = RemoteScanResult(
        ...     success=True,
        ...     scan_id="scan-123",
        ...     status=ScanStatus.COMPLETED,
        ...     hostname="192.168.1.100",
        ...     result_files={
        ...         "xml": Path("/app/data/results/scan-123_results.xml"),
        ...         "html": Path("/app/data/results/scan-123_report.html"),
        ...     },
        ...     files_transferred=3,
        ... )
    """

    hostname: str = ""
    result_files: Dict[str, Path] = field(default_factory=dict)
    files_transferred: int = 0
    remote_dir: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert remote result to dictionary for JSON serialization.

        Returns:
            Dictionary representation including remote-specific fields.
        """
        base_dict = super().to_dict()
        base_dict.update(
            {
                "hostname": self.hostname,
                "result_files": {k: str(v) for k, v in self.result_files.items()},
                "files_transferred": self.files_transferred,
                "remote_dir": self.remote_dir,
            }
        )
        return base_dict


@dataclass
class LocalScanResult(ScanResult):
    """
    Result from local SCAP scan execution.

    Extends ScanResult with data specific to local execution
    where scans run on the same host as OpenWatch.

    Attributes:
        content_path: Path to SCAP content file used
        result_files: Mapping of result type to file path
        profile_id: XCCDF profile ID evaluated

    Usage:
        >>> result = LocalScanResult(
        ...     success=True,
        ...     scan_id="scan-456",
        ...     status=ScanStatus.COMPLETED,
        ...     content_path=Path("/app/data/scap/ssg-rhel8-ds.xml"),
        ...     profile_id="xccdf_org.ssgproject.content_profile_stig",
        ... )
    """

    content_path: Path = field(default_factory=lambda: Path())
    result_files: Dict[str, Path] = field(default_factory=dict)
    profile_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert local result to dictionary for JSON serialization.

        Returns:
            Dictionary representation including local-specific fields.
        """
        base_dict = super().to_dict()
        base_dict.update(
            {
                "content_path": str(self.content_path),
                "result_files": {k: str(v) for k, v in self.result_files.items()},
                "profile_id": self.profile_id,
            }
        )
        return base_dict


@dataclass(frozen=True)
class ScannerCapabilities:
    """
    Describes capabilities of a scanner implementation.

    Used by the scanner registry to determine which scanner
    can handle a given scan request.

    Attributes:
        provider: Scanner provider type
        supported_scan_types: List of scan types this scanner handles
        supported_formats: List of content formats (xccdf, oval, datastream)
        supports_remote: Whether scanner can execute remotely
        supports_local: Whether scanner can execute locally
        max_concurrent: Maximum concurrent scans (0 = unlimited)
    """

    provider: ScanProvider
    supported_scan_types: List[ScanType] = field(default_factory=list)
    supported_formats: List[str] = field(default_factory=list)
    supports_remote: bool = True
    supports_local: bool = True
    max_concurrent: int = 0

    def can_handle(self, scan_type: ScanType, execution_mode: ExecutionMode) -> bool:
        """
        Check if scanner can handle the given scan configuration.

        Args:
            scan_type: Type of scan requested.
            execution_mode: Where scan should execute.

        Returns:
            True if scanner can handle this configuration.
        """
        # Check scan type support
        if scan_type not in self.supported_scan_types:
            return False

        # Check execution mode support
        if execution_mode == ExecutionMode.SSH and not self.supports_remote:
            return False
        if execution_mode == ExecutionMode.LOCAL and not self.supports_local:
            return False

        return True


@dataclass(frozen=True)
class FileTransferSpec:
    """
    Specification for file transfer in remote scan execution.

    Used to define files that need to be transferred to/from
    remote hosts during scan execution.

    Attributes:
        local_path: Path on local system
        remote_path: Path on remote system
        direction: Transfer direction ('upload' or 'download')
        required: Whether transfer failure should abort scan
        verify_size: Whether to verify file size after transfer
    """

    local_path: Path
    remote_path: str
    direction: str = "upload"
    required: bool = True
    verify_size: bool = True


# Type aliases for cleaner function signatures
ResultFiles = Dict[str, Path]
FileMapping = Dict[str, str]
ScanMetadata = Dict[str, Any]
